"""device-discovery-lifecycle-and-discovered-devices."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-discovery-lifecycle-and-discovered-devices"
GROUP = "state-machine"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDiscoveredDevices against a non-existent discovery job is rejected; StartDeviceDiscovery
    starts a job in the documented RUNNING state that shows up under ListDeviceDiscoveries'
    RUNNING filter, and ListDiscoveredDevices against the real job succeeds (positive control)."""
    iot = _iot_client(ctx)

    # DeviceDiscoveryId is constrained to ^[A-Za-z0-9]+$ (no hyphens) -- a hyphenated id
    # is rejected as malformed input (ValidationException) before existence is even
    # checked, which would test the wrong error class. This id is syntactically valid
    # and simply never allocated.
    missing_code, missing_code_msg = _error(
        lambda: iot.list_discovered_devices(Identifier="sim2realbogusdiscoveryid0000")
    )
    assert missing_code == "ResourceNotFoundException", missing_code
    assert missing_code_msg == 'Discovery resource not found.', missing_code_msg

    # CUSTOM discovery requires CustomProtocolDetail with a non-empty "Name", and a
    # ControllerIdentifier naming the hub that will run the discovery -- real AWS rejects
    # StartDeviceDiscovery(DiscoveryType="CUSTOM") missing either field.
    controller_id = _create_controller(ctx, iot)
    started = iot.start_device_discovery(
        DiscoveryType="CUSTOM",
        CustomProtocolDetail={"Name": "sim2real-custom-protocol"},
        ControllerIdentifier=controller_id,
    )
    discovery_id = started["Id"]
    assert started["StartedAt"], "expected StartDeviceDiscovery to report a StartedAt timestamp"

    got = iot.get_device_discovery(Identifier=discovery_id)
    assert got["Id"] == discovery_id, f"expected Id {discovery_id!r}, got {got['Id']!r}"
    assert got["Status"] == "RUNNING", f"expected Status 'RUNNING', got {got['Status']!r}"
    assert got["DiscoveryType"] == "CUSTOM", f"expected DiscoveryType 'CUSTOM', got {got['DiscoveryType']!r}"

    running = iot.list_device_discoveries(StatusFilter="RUNNING").get("Items", [])
    assert any(d["Id"] == discovery_id for d in running), (
        f"expected {discovery_id!r} in RUNNING-filtered list, got {running!r}"
    )

    # Positive control: ListDiscoveredDevices against the real, running job succeeds.
    devices_resp = iot.list_discovered_devices(Identifier=discovery_id)
    assert "Items" in devices_resp, f"expected an 'Items' key in the response, got {devices_resp!r}"


def _wifi_barcode() -> str:
    # The AuthenticationMaterial envelope real AWS accepts for WIFI_SETUP_QR_BAR_CODE is
    # "UPC:<valid UPC-A>;SN:<12-digit serial>"; the serial is unique per call.
    return f"UPC:012345678905;SN:{str(uuid.uuid4().int)[:12]}"


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1; the
    # runner's default region (us-west-2) has no endpoint for it, so on real AWS we
    # pin the client's region via ctx.client's region= override, which keeps the
    # runner's leased credentials/endpoint wiring. On an emulator, keep using
    # ctx.client's single shared endpoint.
    return ctx.client("iot-managed-integrations", region="eu-west-1")
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_controller(ctx, iot) -> str:
    resp = iot.create_managed_thing(
        Role="CONTROLLER",
        AuthenticationMaterial=_wifi_barcode(),
        AuthenticationMaterialType="WIFI_SETUP_QR_BAR_CODE",
        Tags={"sim2real": "true"},
    )
    thing_id = resp["Id"]

    def _cleanup():
        try:
            iot.delete_managed_thing(Identifier=thing_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return thing_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
