"""get-predefined-lambda-deployment-configs-traffic-routing-shapes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-predefined-lambda-deployment-configs-traffic-routing-shapes"
GROUP = "lifecycle"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDeploymentConfig on each predefined Lambda config returns the exact
    trafficRoutingConfig object the type implies, canary and linear intervals included.
    """
    cd = ctx.client("codedeploy")

    all_at_once = cd.get_deployment_config(
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce"
    )["deploymentConfigInfo"]
    assert all_at_once["computePlatform"] == "Lambda", all_at_once
    assert all_at_once["trafficRoutingConfig"] == {"type": "AllAtOnce"}, all_at_once

    canary = cd.get_deployment_config(
        deploymentConfigName="CodeDeployDefault.LambdaCanary10Percent5Minutes"
    )["deploymentConfigInfo"]
    assert canary["computePlatform"] == "Lambda", canary
    assert canary["trafficRoutingConfig"] == {
        "type": "TimeBasedCanary",
        "timeBasedCanary": {"canaryPercentage": 10, "canaryInterval": 5},
    }, canary

    linear = cd.get_deployment_config(
        deploymentConfigName="CodeDeployDefault.LambdaLinear10PercentEvery1Minute"
    )["deploymentConfigInfo"]
    assert linear["computePlatform"] == "Lambda", linear
    assert linear["trafficRoutingConfig"] == {
        "type": "TimeBasedLinear",
        "timeBasedLinear": {"linearPercentage": 10, "linearInterval": 1},
    }, linear


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
