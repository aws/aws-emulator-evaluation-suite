"""origin-request-policy-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource; a resource the check
    itself already deleted is left alone."""
    try:
        resp = get_fn(Id=resource_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "").startswith("NoSuch"):
            return
        raise
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

CHECK = "origin-request-policy-lifecycle"
GROUP = 'policies'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Origin request policy CRUD preserves the configured header allow-list end to end."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-orp-")
    created = cf.create_origin_request_policy(OriginRequestPolicyConfig={
        "Name": name,
        "Comment": "fidelity origin request policy",
        "HeadersConfig": {"HeaderBehavior": "whitelist", "Headers": {"Quantity": 1, "Items": ["CloudFront-Viewer-Country"]}},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    })
    policy_id = created["OriginRequestPolicy"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_origin_request_policy, cf.delete_origin_request_policy, policy_id))

    got = cf.get_origin_request_policy(Id=policy_id)
    headers = got["OriginRequestPolicy"]["OriginRequestPolicyConfig"]["HeadersConfig"]["Headers"]["Items"]
    assert headers == ["CloudFront-Viewer-Country"], f"unexpected headers persisted: {headers}"

    cf.delete_origin_request_policy(Id=policy_id, IfMatch=got["ETag"])
    code, message = _error(lambda: cf.get_origin_request_policy(Id=policy_id))
    assert code == "NoSuchOriginRequestPolicy", f"expected NoSuchOriginRequestPolicy, got {code}"
    expected = "The specified origin request policy does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the dead id is not just unreadable, it is unusable: a mutation targeting
    # it must fail too, not merely a read.
    update_code, update_message = _error(lambda: cf.update_origin_request_policy(
        Id=policy_id,
        IfMatch=got["ETag"],
        OriginRequestPolicyConfig={
            "Name": name,
            "Comment": "post-delete update must be rejected",
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    ))
    assert update_code == "NoSuchOriginRequestPolicy", (
        f"expected NoSuchOriginRequestPolicy updating a deleted policy, got {update_code}"
    )
    expected_update = "The specified origin request policy does not exist."
    assert update_message == expected_update, (
        f"expected message {expected_update!r}, got {update_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
