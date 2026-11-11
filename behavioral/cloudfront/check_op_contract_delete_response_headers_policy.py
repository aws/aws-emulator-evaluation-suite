"""op-contract-deleteResponseHeadersPolicy."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteResponseHeadersPolicy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

# AWS managed response headers policy (Managed-SecurityHeadersPolicy).
_MANAGED_POLICY_ID = "67f7725c-6f97-4210-82d7-5512b31e9d03"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteResponseHeadersPolicy: succeeds for a custom policy; a managed
    policy is protected from deletion (IllegalDelete) even with a correct
    ETag; a deleted policy can no longer be fetched (NoSuchResponseHeadersPolicy)."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-rhp-")
    created = cf.create_response_headers_policy(
        ResponseHeadersPolicyConfig={
            "Name": name,
            "Comment": "sim2real behavioral check",
            "CustomHeadersConfig": {
                "Quantity": 1,
                "Items": [
                    {
                        "Header": "X-Sim2real-Behavioral-Check",
                        "Value": "true",
                        "Override": False,
                    }
                ],
            },
        }
    )
    policy_id = created["ResponseHeadersPolicy"]["Id"]
    etag = created["ETag"]
    ctx.on_cleanup(lambda: _safe_delete(cf, policy_id))

    fetched = cf.get_response_headers_policy(Id=policy_id)
    fetched_name = fetched["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"]["Name"]
    assert fetched_name == name, f"expected policy name {name!r}, got {fetched_name!r}"

    # distinct error boundary: managed policies cannot be deleted
    managed = cf.get_response_headers_policy(Id=_MANAGED_POLICY_ID)
    code, message = _error(
        lambda: cf.delete_response_headers_policy(Id=_MANAGED_POLICY_ID, IfMatch=managed["ETag"])
    )
    assert code == "IllegalDelete", f"expected IllegalDelete deleting a managed policy, got {code}"
    assert message == "The request failed because delete is not allowed for this policy.", (
        f"expected the exact refusal message, got {message!r}"
    )

    # effect-absent: the rejected delete must not have touched the managed policy
    still_managed = cf.get_response_headers_policy(Id=_MANAGED_POLICY_ID)
    assert still_managed["ResponseHeadersPolicy"]["Id"] == _MANAGED_POLICY_ID, (
        f"managed policy {_MANAGED_POLICY_ID} should survive a rejected delete, "
        f"got {still_managed['ResponseHeadersPolicy']['Id']}"
    )

    # success path
    cf.delete_response_headers_policy(Id=policy_id, IfMatch=etag)

    code_after, code_after_message = _error(lambda: cf.get_response_headers_policy(Id=policy_id))
    assert code_after == "NoSuchResponseHeadersPolicy", (
        f"expected NoSuchResponseHeadersPolicy after delete, got {code_after}"
    )
    assert code_after_message == "The specified response headers policy does not exist.", (
        f"expected the exact refusal message, got {code_after_message!r}"
    )

    # a mutation on the now-dead id also fails, with the same specific not-found code
    dead_mutation_code, dead_mutation_message = _error(
        lambda: cf.delete_response_headers_policy(Id=policy_id, IfMatch=etag)
    )
    assert dead_mutation_code == "NoSuchResponseHeadersPolicy", (
        f"expected NoSuchResponseHeadersPolicy deleting an already-deleted policy, "
        f"got {dead_mutation_code}"
    )
    assert dead_mutation_message == "The specified response headers policy does not exist.", (
        f"expected the exact refusal message, got {dead_mutation_message!r}"
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
        current = cf.get_response_headers_policy(Id=policy_id)
        cf.delete_response_headers_policy(Id=policy_id, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResponseHeadersPolicy":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
