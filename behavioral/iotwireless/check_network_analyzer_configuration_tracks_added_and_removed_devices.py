"""network-analyzer-configuration-tracks-added-and-removed-devices."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-analyzer-configuration-tracks-added-and-removed-devices"
GROUP = 'network-analyzer-configuration'
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
    """UpdateNetworkAnalyzerConfiguration's WirelessDevicesToAdd/ToRemove edit the tracked
    device set, and GetNetworkAnalyzerConfiguration reflects exactly the current membership.
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

    def make_device(suffix: str) -> str:
        dev_eui = secrets.token_hex(8)
        created = c.create_wireless_device(
            Type="LoRaWAN",
            Name=ctx.unique_name(f"sim2real-behav-iotw-wd-{suffix}-"),
            DestinationName=dest_name,
            LoRaWAN={
                "DeviceProfileId": device_profile_id,
                "ServiceProfileId": service_profile_id,
                "DevEui": dev_eui,
                "OtaaV1_0_x": {"AppKey": secrets.token_hex(16), "AppEui": secrets.token_hex(8)},
            },
        )
        device_id = created["Id"]
        ctx.on_cleanup(
            _teardown(lambda: c.delete_wireless_device(Id=device_id), "ResourceNotFoundException")
        )
        return device_id

    device_a = make_device("a")
    device_b = make_device("b")

    config_name = ctx.unique_name("sim2real-behav-iotw-nac-")
    c.create_network_analyzer_configuration(Name=config_name)
    ctx.on_cleanup(
        _teardown(
            lambda: c.delete_network_analyzer_configuration(ConfigurationName=config_name),
            "ResourceNotFoundException",
        )
    )

    empty = c.get_network_analyzer_configuration(ConfigurationName=config_name)
    assert empty["WirelessDevices"] == [], (
        f"a fresh configuration must track no devices, got {empty['WirelessDevices']!r}"
    )

    c.update_network_analyzer_configuration(
        ConfigurationName=config_name, WirelessDevicesToAdd=[device_a, device_b]
    )
    both = c.get_network_analyzer_configuration(ConfigurationName=config_name)
    assert set(both["WirelessDevices"]) == {device_a, device_b}, (
        f"expected both devices tracked, got {both['WirelessDevices']!r}"
    )

    c.update_network_analyzer_configuration(
        ConfigurationName=config_name, WirelessDevicesToRemove=[device_a]
    )
    one_left = c.get_network_analyzer_configuration(ConfigurationName=config_name)
    assert one_left["WirelessDevices"] == [device_b], (
        f"expected only device_b left tracked, got {one_left['WirelessDevices']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
