"""wireless-device-mac-version-must-match-device-profile."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wireless-device-mac-version-must-match-device-profile"
GROUP = 'wireless-device-validation'
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWirelessDevice rejects OTAA 1.1 key material against a device profile whose
    MacVersion is 1.0.3, and accepts the same device against a profile that matches.
    """
    c = ctx.client("iotwireless")

    mismatched_profile = c.create_device_profile(
        Name=ctx.unique_name("sim2real-behav-iotw-dp-mismatch-"), LoRaWAN={"MacVersion": "1.0.3"}
    )
    mismatched_id = mismatched_profile["Id"]
    ctx.on_cleanup(lambda: c.delete_device_profile(Id=mismatched_id))

    matching_profile = c.create_device_profile(
        Name=ctx.unique_name("sim2real-behav-iotw-dp-match-"), LoRaWAN={"MacVersion": "1.1"}
    )
    matching_id = matching_profile["Id"]
    ctx.on_cleanup(lambda: c.delete_device_profile(Id=matching_id))

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

    def otaa_v1_1(dev_eui: str, app_eui: str) -> dict:
        return {
            "AppKey": secrets.token_hex(16),
            "NwkKey": secrets.token_hex(16),
            "JoinEui": app_eui,
        }

    mismatched_eui = secrets.token_hex(8)
    code, message = _error(
        lambda: c.create_wireless_device(
            Type="LoRaWAN",
            Name=ctx.unique_name("sim2real-behav-iotw-wd-mismatch-"),
            DestinationName=dest_name,
            LoRaWAN={
                "DeviceProfileId": mismatched_id,
                "ServiceProfileId": service_profile_id,
                "DevEui": mismatched_eui,
                "OtaaV1_1": otaa_v1_1(mismatched_eui, secrets.token_hex(8)),
            },
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        "Validation error: the input profile version is not match macVersion defines in "
        "deviceProfile: 1.0.3"
    ), f"unexpected message {message!r}"

    listed = c.list_wireless_devices(MaxResults=50)["WirelessDeviceList"]
    assert mismatched_eui not in {d["LoRaWAN"]["DevEui"] for d in listed if "LoRaWAN" in d}, (
        "the rejected device must not exist: its DevEui showed up in ListWirelessDevices"
    )

    matching_eui = secrets.token_hex(8)
    created = c.create_wireless_device(
        Type="LoRaWAN",
        Name=ctx.unique_name("sim2real-behav-iotw-wd-match-"),
        DestinationName=dest_name,
        LoRaWAN={
            "DeviceProfileId": matching_id,
            "ServiceProfileId": service_profile_id,
            "DevEui": matching_eui,
            "OtaaV1_1": otaa_v1_1(matching_eui, secrets.token_hex(8)),
        },
    )
    device_id = created["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_wireless_device(Id=device_id), "ResourceNotFoundException"))

    got = c.get_wireless_device(Identifier=device_id, IdentifierType="WirelessDeviceId")
    assert got["LoRaWAN"]["DeviceProfileId"] == matching_id, (
        f"expected DeviceProfileId {matching_id!r}, got {got['LoRaWAN']['DeviceProfileId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
