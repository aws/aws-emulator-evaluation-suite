"""create-deployment-config-server-with-traffic-routing-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-config-server-with-traffic-routing-rejected"
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
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Server config MUST NOT carry a trafficRoutingConfig ->
    InvalidTrafficRoutingConfigurationException, and the rejected config must never come into
    existence."""
    cd = ctx.client("codedeploy")
    good_name = ctx.unique_name("sim2real-behav-" + "dpcfg-good-routing-")
    bad_name = ctx.unique_name("sim2real-behav-" + "dpcfg-bad-routing-")

    # Positive control: this account can create a Server deployment config at all, so the
    # rejection below is specific to pairing Server with trafficRoutingConfig, not a broader
    # inability to create Server configs.
    cd.create_deployment_config(
        deploymentConfigName=good_name,
        computePlatform="Server",
        minimumHealthyHosts={"type": "HOST_COUNT", "value": 1},
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_config(deploymentConfigName=good_name))

    code, message = _error(
        lambda: cd.create_deployment_config(
            deploymentConfigName=bad_name,
            computePlatform="Server",
            minimumHealthyHosts={"type": "HOST_COUNT", "value": 1},
            trafficRoutingConfig={
                "type": "TimeBasedCanary",
                "timeBasedCanary": {"canaryPercentage": 10, "canaryInterval": 5},
            },
        )
    )
    assert code == "InvalidTrafficRoutingConfigurationException", code
    assert message == "Traffic routing configuration should be null for Server deployment configuration", message

    # Independent terminal read: the rejected config never came into existence.
    absent_code, absent_message = _error(lambda: cd.get_deployment_config(deploymentConfigName=bad_name))
    assert absent_code == "DeploymentConfigDoesNotExistException", (
        f"expected DeploymentConfigDoesNotExistException, got {absent_code!r}"
    )
    assert absent_message == f"No deployment configuration found for name: {bad_name}", absent_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
