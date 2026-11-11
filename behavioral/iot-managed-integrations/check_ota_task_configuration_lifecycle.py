"""ota-task-configuration-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ota-task-configuration-lifecycle"
GROUP = "crud-depth"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOtaTaskConfiguration/GetOtaTaskConfiguration/DeleteOtaTaskConfiguration
    round-trip Name and Description."""
    iot = _iot_client(ctx)
    name = ctx.unique_name("sim2real-otacfg-")

    created = iot.create_ota_task_configuration(
        Name=name,
        Description="ota rollout config",
        PushConfig={
            "RolloutConfig": {"MaximumPerMinute": 5},
            "TimeoutConfig": {"InProgressTimeoutInMinutes": 60},
        },
    )
    config_id = created["TaskConfigurationId"]
    ctx.on_cleanup(lambda: _delete_config_ignore_missing(iot, config_id))

    got = iot.get_ota_task_configuration(Identifier=config_id)
    assert got["Name"] == name
    assert got["Description"] == "ota rollout config"

    iot.delete_ota_task_configuration(Identifier=config_id)
    code, code_msg = _error(lambda: iot.get_ota_task_configuration(Identifier=config_id))
    assert code == "ResourceNotFoundException", code
    assert code_msg == f"OTA task configuration not found for id: {config_id}", code_msg

    second_delete_code, second_delete_code_msg = _error(lambda: iot.delete_ota_task_configuration(Identifier=config_id))
    assert second_delete_code == "ResourceNotFoundException", second_delete_code
    assert second_delete_code_msg == 'Failed to delete Ota task configuration, resource does not exist.', second_delete_code_msg


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1, so pin the region
    # via ctx.client's `region=` override, which keeps ctx's credentials and endpoint wiring.
    from botocore.config import Config

    return ctx.client(
        "iot-managed-integrations",
        region="eu-west-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_config_ignore_missing(iot, config_id: str) -> None:
    try:
        iot.delete_ota_task_configuration(Identifier=config_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
