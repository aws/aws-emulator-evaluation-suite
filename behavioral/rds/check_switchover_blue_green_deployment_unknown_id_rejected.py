"""switchover-blue-green-deployment-unknown-id-rejected."""
from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "switchover-blue-green-deployment-unknown-id-rejected"
GROUP = "blue_green_deployments"
SERVICES = ["rds"]

ERR_NOT_FOUND = "BlueGreenDeploymentNotFoundFault"


def _error_code(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SwitchoverBlueGreenDeployment on an identifier that was never issued is rejected with
    BlueGreenDeploymentNotFoundFault; an unrelated, supported call still succeeds."""
    rds = ctx.client("rds")
    # A real BlueGreenDeploymentIdentifier is "bgd-" plus a 26-character lowercase/digit
    # suffix; derive one deterministically from a unique name so it matches that shape but
    # was never issued by AWS.
    suffix = hashlib.sha256(ctx.unique_name("sim2real-behav-bgd-").encode()).hexdigest()[:26]
    bogus_id = f"bgd-{suffix}"

    code, message = _error_code(
        lambda: rds.switchover_blue_green_deployment(BlueGreenDeploymentIdentifier=bogus_id)
    )
    assert code == ERR_NOT_FOUND, f"unexpected error code: {code!r}"
    expected = f"Blue Green Deployment '{bogus_id}' doesn't exist."
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Positive control: an unrelated, supported create call succeeds.
    pg_name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real positive control",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))
    created = rds.describe_db_parameter_groups(DBParameterGroupName=pg_name)["DBParameterGroups"]
    assert len(created) == 1 and created[0]["DBParameterGroupName"] == pg_name, (
        f"expected exactly one parameter group named {pg_name!r}, got {created!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
