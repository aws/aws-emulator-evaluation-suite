"""create-deployment-config-duplicate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-config-duplicate"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']

def _create_deployment_config(ctx, *, min_healthy_type="HOST_COUNT", min_healthy_value=1):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-dpcfg-")
    cd.create_deployment_config(
        deploymentConfigName=name,
        computePlatform="Server",
        minimumHealthyHosts={"type": min_healthy_type, "value": min_healthy_value},
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_config(deploymentConfigName=name))
    return name


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected DeploymentConfigAlreadyExistsException, but the call SUCCEEDED and returned {result!r}"
    )

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Duplicate CreateDeploymentConfig -> DeploymentConfigAlreadyExistsException, the
    existing config's minimumHealthyHosts is left unchanged, and creating a config under a
    different name still succeeds (positive control)."""
    cd = ctx.client("codedeploy")
    name = _create_deployment_config(ctx, min_healthy_value=1)
    code, message = _error(
        lambda: cd.create_deployment_config(
            deploymentConfigName=name,
            minimumHealthyHosts={"type": "HOST_COUNT", "value": 42},
        )
    )
    assert code == "DeploymentConfigAlreadyExistsException", code
    assert message == f"{name} already exists.", message

    # Effect absent: the rejected duplicate did not overwrite the existing config.
    info = cd.get_deployment_config(deploymentConfigName=name)["deploymentConfigInfo"]
    assert info["minimumHealthyHosts"] == {"type": "HOST_COUNT", "value": 1}, info

    # Positive control: a different name is unaffected and still succeeds.
    other_name = _create_deployment_config(ctx, min_healthy_value=2)
    other_info = cd.get_deployment_config(deploymentConfigName=other_name)["deploymentConfigInfo"]
    assert other_info["minimumHealthyHosts"] == {"type": "HOST_COUNT", "value": 2}, other_info


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
