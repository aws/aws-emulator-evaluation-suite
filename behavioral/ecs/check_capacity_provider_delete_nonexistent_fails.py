"""capacity-provider-delete-nonexistent-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-provider-delete-nonexistent-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a capacity provider that was never created must fail
    (overly-permissive check)."""
    ecs = ctx.client("ecs")
    bogus = ctx.unique_name("sim2real-behav-ecs-cp-missing-")
    code, message = _error(lambda: ecs.delete_capacity_provider(capacityProvider=bogus))
    assert code == "ClientException", f"unexpected error code: {code}"
    assert message == "Failed to get info for provided CapacityProvider", f"unexpected message: {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
