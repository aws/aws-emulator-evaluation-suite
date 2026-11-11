"""list-workspace-instances-invalid-provision-state-enum-validation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-workspace-instances-invalid-provision-state-enum-validation"
GROUP = "error-semantics"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListWorkspaceInstances rejects a ProvisionStates filter value that is not one of the
    ProvisionStateEnum members with ValidationException, evaluated server-side (the value is a
    plain string client-side, so the request reaches the service)."""
    wsi = ctx.client("workspaces-instances")

    code, message = _error(lambda: wsi.list_workspace_instances(ProvisionStates=["NOT_A_REAL_STATE"]))
    assert code == "ValidationException", (code, message)
    assert message == (
        "1 validation error detected: Value at 'provisionStates' failed to satisfy constraint: "
        "Member must satisfy constraint: [Member must satisfy enum value set: [DEALLOCATED, "
        "ALLOCATED, ERROR_ALLOCATING, ERROR_DEALLOCATING, ALLOCATING, DEALLOCATING]]"
    ), message

    # positive control: a valid enum value is accepted (may legitimately return zero items)
    wsi.list_workspace_instances(ProvisionStates=["ALLOCATED"])


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
