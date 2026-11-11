"""delete-identity-pool-second-delete-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identity-pool-second-delete-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an already-deleted identity pool a second time returns
    ResourceNotFoundException (delete is a terminal state transition, not idempotent)."""
    cip = ctx.client("cognito-identity")

    pool_id = cip.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]

    # first delete succeeds
    cip.delete_identity_pool(IdentityPoolId=pool_id)

    # confirm the pool is genuinely gone, not merely reporting success cosmetically
    not_found = ("ResourceNotFoundException", f"IdentityPool '{pool_id}' not found.")
    describe_err = _error(lambda: cip.describe_identity_pool(IdentityPoolId=pool_id))
    assert describe_err == not_found, (
        f"expected pool to be gone after first delete ({not_found}), got {describe_err}"
    )

    # second delete of the same (now nonexistent) pool is rejected
    second_delete_err = _error(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))
    assert second_delete_err == not_found, (
        f"expected {not_found} on second delete, got {second_delete_err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
