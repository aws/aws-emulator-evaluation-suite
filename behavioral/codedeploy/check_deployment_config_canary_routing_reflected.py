"""deployment-config-canary-routing-reflected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deployment-config-canary-routing-reflected"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']


def _error(fn):
    """Call fn(); return (code, message) of its botocore error; an unexpected SUCCESS raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Lambda TimeBasedCanary config round-trips its trafficRoutingConfig, and
    deleting it makes it genuinely gone: an independent GetDeploymentConfig fails
    with the specific not-found code, not a silent success.
    """
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-" + "dpcfg-canary-")
    cd.create_deployment_config(
        deploymentConfigName=name,
        computePlatform="Lambda",
        trafficRoutingConfig={
            "type": "TimeBasedCanary",
            "timeBasedCanary": {"canaryPercentage": 10, "canaryInterval": 5},
        },
    )
    ctx.on_cleanup(lambda a=name: cd.delete_deployment_config(deploymentConfigName=a))

    info = cd.get_deployment_config(deploymentConfigName=name)[
        "deploymentConfigInfo"
    ]
    assert info["computePlatform"] == "Lambda", info
    trc = info["trafficRoutingConfig"]
    assert trc["type"] == "TimeBasedCanary", trc
    assert trc["timeBasedCanary"]["canaryPercentage"] == 10, trc
    assert trc["timeBasedCanary"]["canaryInterval"] == 5, trc

    cd.delete_deployment_config(deploymentConfigName=name)
    code, message = _error(lambda: cd.get_deployment_config(deploymentConfigName=name))
    assert code == "DeploymentConfigDoesNotExistException", (
        f"expected DeploymentConfigDoesNotExistException reading a deleted config, got {code}"
    )
    assert message == f"No deployment configuration found for name: {name}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
