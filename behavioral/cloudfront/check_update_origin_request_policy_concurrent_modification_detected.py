"""update-origin-request-policy-concurrent-modification-detected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-origin-request-policy-concurrent-modification-detected"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOriginRequestPolicy with an ETag a concurrent update superseded fails with PreconditionFailed and its
    exact message, leaving the winner's Comment and ETag in place; an update with the current ETag applies."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2realORP")

    def _config(comment):
        return {
            "Comment": comment,
            "Name": name,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        }

    created = cf.create_origin_request_policy(OriginRequestPolicyConfig=_config("v1"))
    policy_id = created["OriginRequestPolicy"]["Id"]
    etag1 = created["ETag"]

    def _cleanup():
        try:
            etag = cf.get_origin_request_policy(Id=policy_id)["ETag"]
            cf.delete_origin_request_policy(Id=policy_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchOriginRequestPolicy":
                raise

    ctx.on_cleanup(_cleanup)

    # Simulate a concurrent caller applying an update using etag1.
    winner = cf.update_origin_request_policy(
        Id=policy_id, IfMatch=etag1, OriginRequestPolicyConfig=_config("v2-winner")
    )
    etag2 = winner["ETag"]
    assert etag2 != etag1, f"expected a fresh ETag after update, got unchanged {etag2!r}"

    # A second caller still holding the stale etag1 tries to update -> must be rejected.
    code, message = _error(
        lambda: cf.update_origin_request_policy(
            Id=policy_id, IfMatch=etag1, OriginRequestPolicyConfig=_config("v3-loser")
        )
    )
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code}"
    expected_message = "The request failed because it didn't meet the preconditions for this operation."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the winning update's content must still be in place.
    current = cf.get_origin_request_policy(Id=policy_id)
    current_comment = current["OriginRequestPolicy"]["OriginRequestPolicyConfig"]["Comment"]
    assert current_comment == "v2-winner", (
        f"expected the winner's content 'v2-winner' to survive the rejected update, got {current_comment!r}"
    )
    assert current["ETag"] == etag2, (
        f"expected ETag to remain the winner's {etag2!r} after the rejected update, got {current['ETag']!r}"
    )

    # Positive control: the same kind of update succeeds when using the current etag.
    updated = cf.update_origin_request_policy(
        Id=policy_id, IfMatch=etag2, OriginRequestPolicyConfig=_config("v3-ok")
    )
    assert updated["ETag"] != etag2, f"expected a fresh ETag after the current-etag update, got unchanged {etag2!r}"
    final = cf.get_origin_request_policy(Id=policy_id)
    final_comment = final["OriginRequestPolicy"]["OriginRequestPolicyConfig"]["Comment"]
    assert final_comment == "v3-ok", f"expected the current-etag update to land as 'v3-ok', got {final_comment!r}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
