"""multicast-group-device-association-tracks-membership-count."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multicast-group-device-association-tracks-membership-count"
GROUP = 'multicast-group-membership'
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
    """AssociateWirelessDeviceWithMulticastGroup raises NumberOfDevicesInGroup by one and
    DisassociateWirelessDeviceFromMulticastGroup lowers it again, while the group's
    NumberOfDevicesRequested -- a high-water mark -- never decreases.
    """
    c = ctx.client("iotwireless")

    multicast_group = c.create_multicast_group(
        Name=ctx.unique_name("sim2real-behav-iotw-mg-"), LoRaWAN={"RfRegion": "US915", "DlClass": "ClassB"}
    )
    group_id = multicast_group["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_multicast_group(Id=group_id), "ResourceNotFoundException"))

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

    before = c.get_multicast_group(Id=group_id)["LoRaWAN"]
    assert before["NumberOfDevicesInGroup"] == 0, (
        f"expected an empty group before association, got {before['NumberOfDevicesInGroup']!r}"
    )

    c.associate_wireless_device_with_multicast_group(Id=group_id, WirelessDeviceId=device_id)
    ctx.on_cleanup(
        _teardown(
            lambda: c.disassociate_wireless_device_from_multicast_group(Id=group_id, WirelessDeviceId=device_id),
            "ResourceNotFoundException",
        )
    )

    after_associate = c.get_multicast_group(Id=group_id)["LoRaWAN"]
    assert after_associate["NumberOfDevicesInGroup"] == 1, (
        f"expected 1 device in group after associate, got {after_associate['NumberOfDevicesInGroup']!r}"
    )
    assert after_associate["NumberOfDevicesRequested"] == 1, (
        f"expected 1 device requested after associate, got {after_associate['NumberOfDevicesRequested']!r}"
    )

    c.disassociate_wireless_device_from_multicast_group(Id=group_id, WirelessDeviceId=device_id)

    after_disassociate = c.get_multicast_group(Id=group_id)["LoRaWAN"]
    assert after_disassociate["NumberOfDevicesInGroup"] == 0, (
        f"expected 0 devices in group after disassociate, got {after_disassociate['NumberOfDevicesInGroup']!r}"
    )
    assert after_disassociate["NumberOfDevicesRequested"] == 1, (
        "NumberOfDevicesRequested is a high-water mark and must not drop after a disassociate, "
        f"got {after_disassociate['NumberOfDevicesRequested']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
