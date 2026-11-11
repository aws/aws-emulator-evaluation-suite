"""duplicate-dev-eui-rejected-within-account."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-dev-eui-rejected-within-account"
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
    """A second CreateWirelessDevice reusing a claimed DevEui is a ConflictException, and the
    DevEui stays claimed by the first device only -- a sibling DevEui still registers cleanly.
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

    def otaa(app_eui: str) -> dict:
        return {"AppKey": secrets.token_hex(16), "AppEui": app_eui}

    shared_eui = secrets.token_hex(8)
    first = c.create_wireless_device(
        Type="LoRaWAN",
        Name=ctx.unique_name("sim2real-behav-iotw-wd-first-"),
        DestinationName=dest_name,
        LoRaWAN={
            "DeviceProfileId": device_profile_id,
            "ServiceProfileId": service_profile_id,
            "DevEui": shared_eui,
            "OtaaV1_0_x": otaa(secrets.token_hex(8)),
        },
    )
    first_id = first["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_wireless_device(Id=first_id), "ResourceNotFoundException"))

    code, message = _error(
        lambda: c.create_wireless_device(
            Type="LoRaWAN",
            Name=ctx.unique_name("sim2real-behav-iotw-wd-dup-"),
            DestinationName=dest_name,
            LoRaWAN={
                "DeviceProfileId": device_profile_id,
                "ServiceProfileId": service_profile_id,
                "DevEui": shared_eui,
                "OtaaV1_0_x": otaa(secrets.token_hex(8)),
            },
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}: {message!r}"
    assert message == "Device with given DevEui already exists", f"unexpected message {message!r}"

    got_first = c.get_wireless_device(Identifier=first_id, IdentifierType="WirelessDeviceId")
    assert got_first["LoRaWAN"]["DevEui"] == shared_eui, (
        f"the claimed DevEui must still belong to the first device, got {got_first['LoRaWAN']['DevEui']!r}"
    )

    sibling_eui = secrets.token_hex(8)
    sibling = c.create_wireless_device(
        Type="LoRaWAN",
        Name=ctx.unique_name("sim2real-behav-iotw-wd-sibling-"),
        DestinationName=dest_name,
        LoRaWAN={
            "DeviceProfileId": device_profile_id,
            "ServiceProfileId": service_profile_id,
            "DevEui": sibling_eui,
            "OtaaV1_0_x": otaa(secrets.token_hex(8)),
        },
    )
    sibling_id = sibling["Id"]
    ctx.on_cleanup(
        _teardown(lambda: c.delete_wireless_device(Id=sibling_id), "ResourceNotFoundException")
    )
    assert sibling_id != first_id, "the sibling DevEui must register as a distinct device"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
