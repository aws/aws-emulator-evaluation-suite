"""gateway-duplicate-core-device-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-duplicate-core-device-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGateway with a coreDeviceThingName already used by another gateway fails InvalidRequestException with
    the exact message and leaves that gateway intact; another thing name succeeds, and after the holder is
    deleted the refused call succeeds with the freed name."""
    client = ctx.client("iotsitewise")
    thing_name = ctx.unique_name("sim2real-behav-thing-")

    # positive control: the account and this coreDeviceThingName work at all
    resp_a = client.create_gateway(
        gatewayName=ctx.unique_name("sim2real-behav-gw-"),
        gatewayPlatform={"greengrassV2": {"coreDeviceThingName": thing_name}},
        tags={"sim2real-behav-check": CHECK},
    )
    gw_a_id = resp_a["gatewayId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_gateway(gatewayId=gw_a_id)))

    # break: the same coreDeviceThingName is already claimed by gw_a
    err = _error(lambda: client.create_gateway(
        gatewayName=ctx.unique_name("sim2real-behav-gw-dup-"),
        gatewayPlatform={"greengrassV2": {"coreDeviceThingName": thing_name}},
    ))
    assert err["Code"] == "InvalidRequestException", err
    expected_message = (
        f"Core Device/IoT Core Thing: {thing_name} is already associated with a SiteWise Gateway."
    )
    assert err.get("Message") == expected_message, err

    # effect absent: the original gateway is unaffected by the rejected duplicate
    described = client.describe_gateway(gatewayId=gw_a_id)
    assert described["gatewayId"] == gw_a_id
    assert described["gatewayPlatform"]["greengrassV2"]["coreDeviceThingName"] == thing_name

    # concurrent control: a different core device thing name still succeeds while the
    # conflict stands, so the rejection is specific to the duplicate name, not CreateGateway
    # broadly failing
    other_thing = ctx.unique_name("sim2real-behav-thing2-")
    resp_c = client.create_gateway(
        gatewayName=ctx.unique_name("sim2real-behav-gw-ok-"),
        gatewayPlatform={"greengrassV2": {"coreDeviceThingName": other_thing}},
        tags={"sim2real-behav-check": CHECK},
    )
    gw_c_id = resp_c["gatewayId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_gateway(gatewayId=gw_c_id)))
    assert gw_c_id != gw_a_id
    described_c = client.describe_gateway(gatewayId=gw_c_id)
    assert described_c["gatewayPlatform"]["greengrassV2"]["coreDeviceThingName"] == other_thing

    # restore: release the coreDeviceThingName by deleting the gateway holding it
    client.delete_gateway(gatewayId=gw_a_id)
    gone = _error(lambda: client.describe_gateway(gatewayId=gw_a_id))
    assert gone["Code"] == "ResourceNotFoundException", gone
    expected_gone = (
        f"No gateway with ID {gw_a_id} was found. "
        "Please verify that you supplied the correct gateway ID and try again."
    )
    assert gone.get("Message") == expected_gone, gone

    # the identical call the account just refused now succeeds
    resp_d = client.create_gateway(
        gatewayName=ctx.unique_name("sim2real-behav-gw-restored-"),
        gatewayPlatform={"greengrassV2": {"coreDeviceThingName": thing_name}},
        tags={"sim2real-behav-check": CHECK},
    )
    gw_d_id = resp_d["gatewayId"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_gateway(gatewayId=gw_d_id)))
    assert gw_d_id != gw_a_id

    # terminal read: independent, at the destination — the freed thing name is genuinely usable
    described_d = client.describe_gateway(gatewayId=gw_d_id)
    assert described_d["gatewayPlatform"]["greengrassV2"]["coreDeviceThingName"] == thing_name, described_d


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
