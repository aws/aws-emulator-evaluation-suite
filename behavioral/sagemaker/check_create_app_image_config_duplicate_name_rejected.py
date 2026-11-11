"""create-app-image-config-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-app-image-config-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAppImageConfig reusing an existing AppImageConfigName is rejected with
    ResourceInUse rather than silently overwriting or duplicating the config.
    """
    sm = ctx.client("sagemaker")

    config_name = ctx.unique_name("sim2real-aic-")
    first = sm.create_app_image_config(
        AppImageConfigName=config_name,
        KernelGatewayImageConfig={"KernelSpecs": [{"Name": "python3", "DisplayName": "Python 3"}]},
    )
    ctx.on_cleanup(lambda: sm.delete_app_image_config(AppImageConfigName=config_name))

    # --- negative: recreate under the same name with different content ---
    code, message = _error(
        lambda: sm.create_app_image_config(
            AppImageConfigName=config_name,
            KernelGatewayImageConfig={"KernelSpecs": [{"Name": "python3", "DisplayName": "Different"}]},
        )
    )
    assert code == "ResourceInUse", f"expected ResourceInUse, got {code!r}"
    expected_message = "The ID or Name specified is already in use."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the original config's content was not overwritten
    desc = sm.describe_app_image_config(AppImageConfigName=config_name)
    actual_display_name = desc["KernelGatewayImageConfig"]["KernelSpecs"][0]["DisplayName"]
    assert actual_display_name == "Python 3", (
        f"expected original DisplayName 'Python 3' to survive the rejected create, got {actual_display_name!r}"
    )
    assert desc["AppImageConfigArn"] == first["AppImageConfigArn"], (
        f"expected ARN {first['AppImageConfigArn']!r} unchanged, got {desc['AppImageConfigArn']!r}"
    )

    # --- positive control: a distinctly named config succeeds ---
    other_name = ctx.unique_name("sim2real-aic-other-")
    second = sm.create_app_image_config(
        AppImageConfigName=other_name,
        KernelGatewayImageConfig={"KernelSpecs": [{"Name": "python3", "DisplayName": "Python 3"}]},
    )
    ctx.on_cleanup(lambda: sm.delete_app_image_config(AppImageConfigName=other_name))

    # terminal read: independent of the create call that produced `second`, at the destination
    desc_other = sm.describe_app_image_config(AppImageConfigName=other_name)
    assert desc_other["AppImageConfigArn"] == second["AppImageConfigArn"], (
        f"expected {second['AppImageConfigArn']!r} from an independent describe, got {desc_other['AppImageConfigArn']!r}"
    )
    assert desc_other["AppImageConfigArn"] != first["AppImageConfigArn"], (
        "distinctly-named config resolved to the original config's ARN"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
