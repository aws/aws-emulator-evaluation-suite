"""predefined-deployment-config-delete-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "predefined-deployment-config-delete-rejected"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeploymentConfig on CodeDeployDefault.OneAtATime fails with InvalidOperationException and the config
    stays readable, while a custom deployment config is created and deleted normally.
    """
    cd = ctx.client("codedeploy")

    # Positive control: a custom deployment config can be created and deleted.
    config_name = ctx.unique_name("sim2real-cdconfig-")
    cd.create_deployment_config(
        deploymentConfigName=config_name,
        minimumHealthyHosts={"type": "HOST_COUNT", "value": 1},
    )
    cd.delete_deployment_config(deploymentConfigName=config_name)
    gone = _client_error(lambda: cd.get_deployment_config(deploymentConfigName=config_name))
    assert gone == (
        "DeploymentConfigDoesNotExistException",
        f"No deployment configuration found for name: {config_name}",
    ), f"expected DeploymentConfigDoesNotExistException after deleting the custom config, got {gone!r}"

    # Negative: predefined deployment configs cannot be deleted.
    refused = _client_error(
        lambda: cd.delete_deployment_config(deploymentConfigName="CodeDeployDefault.OneAtATime")
    )
    assert refused == (
        "InvalidOperationException",
        "Can not delete a predefined deployment configuration",
    ), f"expected InvalidOperationException deleting a predefined config, got {refused!r}"

    # Effect absent: the predefined config still exists and is fully usable.
    info = cd.get_deployment_config(deploymentConfigName="CodeDeployDefault.OneAtATime")[
        "deploymentConfigInfo"
    ]
    assert info["deploymentConfigName"] == "CodeDeployDefault.OneAtATime", (
        f"expected CodeDeployDefault.OneAtATime to still exist after the rejected delete, "
        f"got {info.get('deploymentConfigName')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
