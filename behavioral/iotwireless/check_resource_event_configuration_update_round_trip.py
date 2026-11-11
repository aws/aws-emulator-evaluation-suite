"""resource-event-configuration-update-round-trip."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-event-configuration-update-round-trip"
GROUP = 'resource-event-configuration'
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
    """UpdateResourceEventConfiguration's Join.WirelessDeviceIdEventTopic flips independently of
    the other event topics, and GetResourceEventConfiguration reflects exactly that change.
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

    before = c.get_resource_event_configuration(Identifier=device_id, IdentifierType="WirelessDeviceId")
    assert before["Join"]["WirelessDeviceIdEventTopic"] == "Disabled", (
        f"expected Join disabled by default, got {before['Join']['WirelessDeviceIdEventTopic']!r}"
    )
    assert before["DeviceRegistrationState"]["WirelessDeviceIdEventTopic"] == "Disabled", (
        "expected DeviceRegistrationState disabled by default, got "
        f"{before['DeviceRegistrationState']['WirelessDeviceIdEventTopic']!r}"
    )

    c.update_resource_event_configuration(
        Identifier=device_id,
        IdentifierType="WirelessDeviceId",
        Join={"WirelessDeviceIdEventTopic": "Enabled"},
    )

    after = c.get_resource_event_configuration(Identifier=device_id, IdentifierType="WirelessDeviceId")
    assert after["Join"]["WirelessDeviceIdEventTopic"] == "Enabled", (
        f"expected Join enabled after update, got {after['Join']['WirelessDeviceIdEventTopic']!r}"
    )
    assert after["DeviceRegistrationState"]["WirelessDeviceIdEventTopic"] == "Disabled", (
        "updating Join must not flip DeviceRegistrationState, got "
        f"{after['DeviceRegistrationState']['WirelessDeviceIdEventTopic']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
