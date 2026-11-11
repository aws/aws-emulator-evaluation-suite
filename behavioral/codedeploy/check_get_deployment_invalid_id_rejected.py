"""get-deployment-invalid-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-deployment-invalid-id-rejected"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']

def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A malformed deployment id is rejected at input validation
    (InvalidDeploymentIdException) — distinct from the not-found path, proven by a
    well-formed-but-nonexistent id being discriminated on existence instead."""
    cd = ctx.client("codedeploy")
    code, message = _error(
        lambda: cd.get_deployment(deploymentId="not-a-deployment-id")
    )
    assert code == "InvalidDeploymentIdException", (
        f"expected InvalidDeploymentIdException for a malformed id, got {code}"
    )
    assert message == "Specified DeploymentId is not in the valid format: not-a-deployment-id", (
        message
    )

    # positive control: a well-formed but nonexistent id passes the format gate and is
    # discriminated on existence instead - a different, specific error code, proving the
    # format check above is narrow and not a blanket rejection of every GetDeployment call
    well_formed_missing_id = "d-ABCDEFGHI"
    code_missing, message_missing = _error(
        lambda: cd.get_deployment(deploymentId=well_formed_missing_id)
    )
    assert code_missing == "DeploymentDoesNotExistException", (
        f"expected DeploymentDoesNotExistException for a well-formed but nonexistent id, "
        f"got {code_missing}"
    )
    assert message_missing == f"The deployment {well_formed_missing_id} could not be found", (
        message_missing
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
