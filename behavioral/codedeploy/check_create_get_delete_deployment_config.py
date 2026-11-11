"""create-get-delete-deployment-config."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-get-delete-deployment-config"
GROUP = 'lifecycle'
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
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED, returned {result!r}")

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeploymentConfig -> GetDeploymentConfig -> DeleteDeploymentConfig."""
    cd = ctx.client("codedeploy")
    name = _create_deployment_config(ctx)

    info = cd.get_deployment_config(deploymentConfigName=name)[
        "deploymentConfigInfo"
    ]
    assert info["deploymentConfigName"] == name, info
    assert info["computePlatform"] == "Server", info
    assert info["minimumHealthyHosts"] == {"type": "HOST_COUNT", "value": 1}, info
    assert "deploymentConfigId" in info and info["deploymentConfigId"], info

    cd.delete_deployment_config(deploymentConfigName=name)

    expected_message = f"No deployment configuration found for name: {name}"
    code, message = _error(
        lambda: cd.get_deployment_config(deploymentConfigName=name)
    )
    assert code == "DeploymentConfigDoesNotExistException", (
        f"expected DeploymentConfigDoesNotExistException on GetDeploymentConfig "
        f"after delete, got {code!r}"
    )
    assert message == expected_message, message

    # Measured invariant: unlike GetDeploymentConfig, a second DeleteDeploymentConfig
    # on the same dead id is an idempotent no-op success on real AWS, not a
    # DeploymentConfigDoesNotExistException. A double-delete must still never
    # resurrect the resource, so re-assert absence via an independent read after it.
    cd.delete_deployment_config(deploymentConfigName=name)
    redelete_gone_code, redelete_gone_message = _error(
        lambda: cd.get_deployment_config(deploymentConfigName=name)
    )
    assert redelete_gone_code == "DeploymentConfigDoesNotExistException", (
        f"a double-deleted deployment config must not have been resurrected; "
        f"expected DeploymentConfigDoesNotExistException, got {redelete_gone_code!r}"
    )
    assert redelete_gone_message == expected_message, redelete_gone_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
