"""create-deployment-config-invalid-min-healthy-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-config-invalid-min-healthy-rejected"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A valid FLEET_PERCENT config is accepted (positive control); the identical shape with a
    negative minimum-healthy value -> InvalidMinimumHealthyHostValueException, and creates
    nothing under its own name."""
    cd = ctx.client("codedeploy")
    good_name = ctx.unique_name("sim2real-behav-" + "dpcfg-good-")
    bad_name = ctx.unique_name("sim2real-behav-" + "dpcfg-bad-")

    cd.create_deployment_config(
        deploymentConfigName=good_name,
        minimumHealthyHosts={"type": "FLEET_PERCENT", "value": 50},
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_config(deploymentConfigName=good_name))

    info = cd.get_deployment_config(deploymentConfigName=good_name)["deploymentConfigInfo"]
    assert info["minimumHealthyHosts"] == {"type": "FLEET_PERCENT", "value": 50}, info

    code, message = _error(
        lambda: cd.create_deployment_config(
            deploymentConfigName=bad_name,
            minimumHealthyHosts={"type": "FLEET_PERCENT", "value": -5},
        )
    )
    assert code == "InvalidMinimumHealthyHostValueException", code
    assert message == (
        "The value for the minimum healthy hosts with type of FLEET_PERCENT should be "
        "positive and less than 100"
    ), message

    missing, missing_message = _error(lambda: cd.get_deployment_config(deploymentConfigName=bad_name))
    assert missing == "DeploymentConfigDoesNotExistException", missing
    assert missing_message == f"No deployment configuration found for name: {bad_name}", missing_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
