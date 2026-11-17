"""create-deployment-config-predefined-name-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-config-predefined-name-prefix-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeploymentConfig under an existing predefined config's name is rejected with
    InvalidDeploymentConfigNameException naming the reserved prefix, and creates nothing there,
    while an otherwise-identical name outside the reserved prefix succeeds."""
    cd = ctx.client("codedeploy")
    predefined_name = "CodeDeployDefault.LambdaLinear10PercentEvery1Minute"
    before = cd.get_deployment_config(deploymentConfigName=predefined_name)[
        "deploymentConfigInfo"
    ]

    code, message = _error(
        lambda: cd.create_deployment_config(
            deploymentConfigName=predefined_name,
            minimumHealthyHosts={"type": "HOST_COUNT", "value": 1},
        )
    )
    assert code == "InvalidDeploymentConfigNameException", code
    assert message == "The prefix CodeDeployDefault. is reserved for predefined configuration names", message

    # Effect absent: the predefined config's own shape is unchanged by the rejected call.
    after = cd.get_deployment_config(deploymentConfigName=predefined_name)[
        "deploymentConfigInfo"
    ]
    assert after["computePlatform"] == before["computePlatform"], (after, before)
    assert after["trafficRoutingConfig"] == before["trafficRoutingConfig"], (after, before)
    assert "minimumHealthyHosts" not in after, after

    # Positive control: an otherwise-identical create outside the reserved prefix succeeds.
    good_name = ctx.unique_name("sim2real-behav-dpcfg-notprefixed-")
    cd.create_deployment_config(
        deploymentConfigName=good_name,
        minimumHealthyHosts={"type": "HOST_COUNT", "value": 1},
    )
    ctx.on_cleanup(lambda a=good_name: cd.delete_deployment_config(deploymentConfigName=a))
    good = cd.get_deployment_config(deploymentConfigName=good_name)["deploymentConfigInfo"]
    assert good["minimumHealthyHosts"] == {"type": "HOST_COUNT", "value": 1}, good


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
