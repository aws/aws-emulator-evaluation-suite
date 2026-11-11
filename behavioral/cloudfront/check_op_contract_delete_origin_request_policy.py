"""op-contract-deleteOriginRequestPolicy."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteOriginRequestPolicy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

# A well-known AWS managed origin request policy (Managed-AllViewer). Managed
# policies can never be deleted by a caller, regardless of ETag correctness.
_MANAGED_POLICY_ID = "216adef6-5c7f-47e4-b989-5492eafa07d3"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteOriginRequestPolicy on a managed policy is refused with IllegalDelete and the exact message and
    leaves it in place, while on a custom policy it succeeds, after which a read and a second delete
    return NoSuchOriginRequestPolicy."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-orp-")
    config = {
        "Name": name,
        "Comment": "sim2real behavioral check",
        "HeadersConfig": {"HeaderBehavior": "none"},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    }
    created = cf.create_origin_request_policy(OriginRequestPolicyConfig=config)
    policy_id = created["OriginRequestPolicy"]["Id"]
    etag = created["ETag"]
    ctx.on_cleanup(lambda: _safe_delete(cf, policy_id))

    # sanity: freshly created policy is fetchable
    fetched = cf.get_origin_request_policy(Id=policy_id)
    fetched_name = fetched["OriginRequestPolicy"]["OriginRequestPolicyConfig"]["Name"]
    assert fetched_name == name, f"expected freshly created policy name {name!r}, got {fetched_name!r}"

    # distinct error boundary #1: managed/predefined policies are immutable-delete
    managed = cf.get_origin_request_policy(Id=_MANAGED_POLICY_ID)
    managed_etag = managed["ETag"]
    code, message = _error(
        lambda: cf.delete_origin_request_policy(Id=_MANAGED_POLICY_ID, IfMatch=managed_etag)
    )
    assert code == "IllegalDelete", f"expected IllegalDelete deleting a managed policy, got {code}"
    assert message == "The request failed because delete is not allowed for this policy.", (
        f"expected the exact refusal message, got {message!r}"
    )

    # effect absent: the rejected delete did not remove the managed policy
    still_managed = cf.get_origin_request_policy(Id=_MANAGED_POLICY_ID)
    assert still_managed["OriginRequestPolicy"]["Id"] == _MANAGED_POLICY_ID, (
        "expected the managed policy to still exist after its delete was rejected"
    )

    # success path
    cf.delete_origin_request_policy(Id=policy_id, IfMatch=etag)

    # distinct error boundary #2: the policy is gone after deletion
    code_after, code_after_message = _error(lambda: cf.get_origin_request_policy(Id=policy_id))
    assert code_after == "NoSuchOriginRequestPolicy", (
        f"expected NoSuchOriginRequestPolicy after delete, got {code_after}"
    )
    assert code_after_message == "The specified origin request policy does not exist.", (
        f"expected the exact refusal message, got {code_after_message!r}"
    )

    # a further mutation on the dead id fails the same way, not e.g. a stale-ETag error
    code_delete_again, code_delete_again_message = _error(
        lambda: cf.delete_origin_request_policy(Id=policy_id, IfMatch=etag)
    )
    assert code_delete_again == "NoSuchOriginRequestPolicy", (
        f"expected NoSuchOriginRequestPolicy deleting an already-deleted policy, got {code_delete_again}"
    )
    assert code_delete_again_message == "The specified origin request policy does not exist.", (
        f"expected the exact refusal message, got {code_delete_again_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete(cf, policy_id: str) -> None:
    try:
        current = cf.get_origin_request_policy(Id=policy_id)
        cf.delete_origin_request_policy(Id=policy_id, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchOriginRequestPolicy":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
