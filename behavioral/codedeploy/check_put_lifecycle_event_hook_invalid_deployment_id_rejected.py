"""put-lifecycle-event-hook-invalid-deployment-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-lifecycle-event-hook-invalid-deployment-id-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLifecycleEventHookExecutionStatus and GetDeployment reject a malformed deployment ID with the same
    InvalidDeploymentIdException, while a well-formed unknown ID fails with DeploymentDoesNotExistException
    instead.
    """
    cd = ctx.client("codedeploy")

    malformed_id = "not a valid deployment id !!"
    malformed_error = (
        "InvalidDeploymentIdException",
        f"Specified DeploymentId is not in the valid format: {malformed_id}",
    )
    error = _client_error(
        lambda: cd.put_lifecycle_event_hook_execution_status(
            deploymentId=malformed_id,
            lifecycleEventHookExecutionId="1",
            status="Succeeded",
        )
    )
    assert error == malformed_error, (
        f"malformed deploymentId {malformed_id!r} should raise {malformed_error!r}, got {error!r}"
    )

    # effect absent: the same malformed id never materializes any deployment elsewhere either
    error_get = _client_error(lambda: cd.get_deployment(deploymentId=malformed_id))
    assert error_get == malformed_error, (
        f"GetDeployment on the same malformed id {malformed_id!r} should raise "
        f"{malformed_error!r} (no phantom deployment materialized), got {error_get!r}"
    )

    # positive control: a well-formed but nonexistent deployment id passes the format gate and
    # is discriminated on existence instead - a different, specific error code
    well_formed_missing_id = "d-ABCDEFGHI"
    error_wellformed = _client_error(
        lambda: cd.put_lifecycle_event_hook_execution_status(
            deploymentId=well_formed_missing_id,
            lifecycleEventHookExecutionId="1",
            status="Succeeded",
        )
    )
    assert error_wellformed == (
        "DeploymentDoesNotExistException",
        f"The deployment {well_formed_missing_id} could not be found",
    ), (
        f"well-formed but nonexistent deploymentId {well_formed_missing_id!r} should raise "
        f"DeploymentDoesNotExistException (format gate passed, discriminated on existence), "
        f"got {error_wellformed!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
