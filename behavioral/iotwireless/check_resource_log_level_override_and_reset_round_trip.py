"""resource-log-level-override-and-reset-round-trip."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-log-level-override-and-reset-round-trip"
GROUP = 'resource-log-level'
SERVICES = ['iotwireless']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourceLogLevel overrides a wireless device's log level, GetResourceLogLevel reflects
    it, and ResetResourceLogLevel clears the override back to having none set.
    """
    c = ctx.client("iotwireless")

    device_profile = c.create_device_profile(
        Name=ctx.unique_name("sim2real-behav-iotw-dp-"), LoRaWAN={"MacVersion": "1.0.3"}
    )
    device_profile_id = device_profile["Id"]
    ctx.on_cleanup(lambda: c.delete_device_profile(Id=device_profile_id))

    service_profile = c.create_service_profile(
        Name=ctx.unique_name("sim2real-behav-iotw-sp-"), LoRaWAN={}
    )
    service_profile_id = service_profile["Id"]
    ctx.on_cleanup(lambda: c.delete_service_profile(Id=service_profile_id))

    role = ctx.client("iam").create_role(
        RoleName=ctx.unique_name("sim2real-behav-iotw-destrole-"),
        AssumeRolePolicyDocument=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"iotwireless.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
        ),
    )
    role_name = role["Role"]["RoleName"]
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    dest_name = ctx.unique_name("sim2real-behav-iotw-dest-")
    c.create_destination(
        Name=dest_name, ExpressionType="RuleName", Expression="sim2real_behav_rule", RoleArn=role_arn
    )
    ctx.on_cleanup(lambda: c.delete_destination(Name=dest_name))

    dev_eui = secrets.token_hex(8)
    device = c.create_wireless_device(
        Type="LoRaWAN",
        Name=ctx.unique_name("sim2real-behav-iotw-wd-"),
        DestinationName=dest_name,
        LoRaWAN={
            "DeviceProfileId": device_profile_id,
            "ServiceProfileId": service_profile_id,
            "DevEui": dev_eui,
            "OtaaV1_0_x": {"AppKey": secrets.token_hex(16), "AppEui": secrets.token_hex(8)},
        },
    )
    device_id = device["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_wireless_device(Id=device_id), "ResourceNotFoundException"))

    before = c.get_resource_log_level(ResourceIdentifier=device_id, ResourceType="WirelessDevice")
    assert "LogLevel" not in before, (
        f"expected no override before any Put, got LogLevel {before.get('LogLevel')!r}"
    )

    c.put_resource_log_level(ResourceIdentifier=device_id, ResourceType="WirelessDevice", LogLevel="ERROR")
    overridden = c.get_resource_log_level(ResourceIdentifier=device_id, ResourceType="WirelessDevice")
    assert overridden["LogLevel"] == "ERROR", f"expected LogLevel ERROR, got {overridden['LogLevel']!r}"

    c.reset_resource_log_level(ResourceIdentifier=device_id, ResourceType="WirelessDevice")
    after_reset = c.get_resource_log_level(ResourceIdentifier=device_id, ResourceType="WirelessDevice")
    assert "LogLevel" not in after_reset, (
        f"expected the override cleared after reset, got LogLevel {after_reset.get('LogLevel')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
