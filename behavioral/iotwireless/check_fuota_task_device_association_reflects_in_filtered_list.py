"""fuota-task-device-association-reflects-in-filtered-list."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fuota-task-device-association-reflects-in-filtered-list"
GROUP = 'fuota-task-membership'
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
    """AssociateWirelessDeviceWithFuotaTask makes the device appear in
    ListWirelessDevices(FuotaTaskId=...) with FuotaDeviceStatus Initial, and
    DisassociateWirelessDeviceFromFuotaTask removes it from that filtered list again.
    """
    c = ctx.client("iotwireless")
    iam = ctx.client("iam")

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

    role = iam.create_role(
        RoleName=ctx.unique_name("sim2real-behav-iotw-fuotarole-"),
        AssumeRolePolicyDocument=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"iotwireless.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
        ),
    )
    role_name = role["Role"]["RoleName"]
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

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

    fuota_task = c.create_fuota_task(
        Name=ctx.unique_name("sim2real-behav-iotw-fuota-"),
        FirmwareUpdateImage="s3://sim2real-behav-bucket/firmware-image.bin",
        FirmwareUpdateRole=role_arn,
        LoRaWAN={"RfRegion": "US915"},
    )
    fuota_task_id = fuota_task["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_fuota_task(Id=fuota_task_id), "ResourceNotFoundException"))

    before = c.list_wireless_devices(FuotaTaskId=fuota_task_id)["WirelessDeviceList"]
    assert before == [], f"expected no device associated yet, got {before!r}"

    c.associate_wireless_device_with_fuota_task(Id=fuota_task_id, WirelessDeviceId=device_id)
    ctx.on_cleanup(
        _teardown(
            lambda: c.disassociate_wireless_device_from_fuota_task(Id=fuota_task_id, WirelessDeviceId=device_id),
            "ResourceNotFoundException",
        )
    )

    associated = c.list_wireless_devices(FuotaTaskId=fuota_task_id)["WirelessDeviceList"]
    assert [d["Id"] for d in associated] == [device_id], (
        f"expected only {device_id!r} associated, got {[d['Id'] for d in associated]!r}"
    )
    assert associated[0]["FuotaDeviceStatus"] == "Initial", (
        f"expected FuotaDeviceStatus Initial, got {associated[0]['FuotaDeviceStatus']!r}"
    )

    c.disassociate_wireless_device_from_fuota_task(Id=fuota_task_id, WirelessDeviceId=device_id)
    after = c.list_wireless_devices(FuotaTaskId=fuota_task_id)["WirelessDeviceList"]
    assert after == [], f"expected the device removed from the filtered list, got {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
