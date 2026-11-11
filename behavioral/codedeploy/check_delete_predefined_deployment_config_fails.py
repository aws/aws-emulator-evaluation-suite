"""delete-predefined-deployment-config-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-predefined-deployment-config-fails"
GROUP = 'overly-permissive'
SERVICES = ['codedeploy']

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeploymentConfig on CodeDeployDefault.OneAtATime raises InvalidOperationException and the
    config stays, while a custom deployment config deletes."""
    cd = ctx.client("codedeploy")

    config_name = ctx.unique_name("sim2real-cdconfig-")
    cd.create_deployment_config(
        deploymentConfigName=config_name,
        minimumHealthyHosts={"type": "HOST_COUNT", "value": 1},
    )

    def _cleanup_config():
        try:
            cd.delete_deployment_config(deploymentConfigName=config_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DeploymentConfigDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup_config)
    cd.delete_deployment_config(deploymentConfigName=config_name)
    gone = _client_error(lambda: cd.get_deployment_config(deploymentConfigName=config_name))
    assert gone.get("Code") == "DeploymentConfigDoesNotExistException", (
        f"the positive control's custom config was not actually deleted: {gone!r}"
    )
    assert gone.get("Message") == f"No deployment configuration found for name: {config_name}", (
        gone
    )

    error = _client_error(
        lambda: cd.delete_deployment_config(
            deploymentConfigName="CodeDeployDefault.OneAtATime"
        )
    )
    assert error.get("Code") == "InvalidOperationException", (
        f"deleting a predefined deployment config returned {error.get('Code')!r}, "
        f"expected 'InvalidOperationException'"
    )
    assert error.get("Message") == "Can not delete a predefined deployment configuration", error

    info = cd.get_deployment_config(
        deploymentConfigName="CodeDeployDefault.OneAtATime"
    )["deploymentConfigInfo"]
    assert info["deploymentConfigName"] == "CodeDeployDefault.OneAtATime", (
        f"the predefined config no longer reads back by name after the rejected delete: {info!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
