"""get-origin-request-policy-config-empty-vs-absent-lists-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-origin-request-policy-config-empty-vs-absent-lists-preserved"
GROUP = "representation"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOriginRequestPolicyConfig keeps an omitted Comment distinct from an explicit empty one,
    keeps identical list sub-configs equal, and a deleted policy reads and deletes as missing."""
    cf = ctx.client("cloudfront")

    name_absent = ctx.unique_name("sim2real-orp-absent-")
    name_empty = ctx.unique_name("sim2real-orp-empty-")

    base_lists = {
        "HeadersConfig": {"HeaderBehavior": "none"},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    }

    config_absent = {"Name": name_absent, **base_lists}
    resp_a = cf.create_origin_request_policy(OriginRequestPolicyConfig=config_absent)
    policy_a_id = resp_a["OriginRequestPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_policy(ctx, policy_a_id))

    config_empty = {"Name": name_empty, "Comment": "", **base_lists}
    resp_b = cf.create_origin_request_policy(OriginRequestPolicyConfig=config_empty)
    policy_b_id = resp_b["OriginRequestPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_policy(ctx, policy_b_id))

    got_a = cf.get_origin_request_policy_config(Id=policy_a_id)["OriginRequestPolicyConfig"]
    got_b = cf.get_origin_request_policy_config(Id=policy_b_id)["OriginRequestPolicyConfig"]

    comment_a = got_a.get("Comment")
    comment_b = got_b.get("Comment")
    assert comment_b == "", f"expected explicit empty Comment to round-trip as '', got {comment_b!r}"
    assert comment_a != comment_b, (
        f"expected omitted-Comment and explicit-empty-Comment to round-trip "
        f"DIFFERENTLY, got the same Comment={comment_a!r} for both -- the "
        f"distinction between absent and explicitly-empty was collapsed"
    )

    # Lists are left canonical: Behavior "none" rejects any Headers/Cookies/QueryStrings
    # sub-object, and list behaviors require Items even at Quantity=0.
    for key in ("HeadersConfig", "CookiesConfig", "QueryStringsConfig"):
        assert got_a[key] == got_b[key], (
            f"{key} diverged despite identical canonical submission: "
            f"{got_a[key]!r} vs {got_b[key]!r}"
        )

    etag_b = cf.get_origin_request_policy(Id=policy_b_id)["ETag"]
    cf.delete_origin_request_policy(Id=policy_b_id, IfMatch=etag_b)

    err, message = _error(lambda: cf.get_origin_request_policy_config(Id=policy_b_id))
    assert err == "NoSuchOriginRequestPolicy", (
        f"expected deleted policy B to 404 as NoSuchOriginRequestPolicy on an "
        f"independent read, got {err!r}"
    )
    assert message == "The specified origin request policy does not exist.", (
        f"expected AWS's exact not-found message for the deleted policy, got {message!r}"
    )
    err2, message2 = _error(
        lambda: cf.delete_origin_request_policy(Id=policy_b_id, IfMatch=etag_b)
    )
    assert err2 == "NoSuchOriginRequestPolicy", (
        f"expected a delete of the already-deleted policy B to fail with "
        f"NoSuchOriginRequestPolicy, got {err2!r}"
    )
    assert message2 == "The specified origin request policy does not exist.", (
        f"expected AWS's exact not-found message for the repeated delete, got {message2!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message); raise if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


def _delete_policy(ctx, policy_id: str) -> None:
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_origin_request_policy(Id=policy_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchOriginRequestPolicy":
            return
        raise
    cf.delete_origin_request_policy(Id=policy_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
