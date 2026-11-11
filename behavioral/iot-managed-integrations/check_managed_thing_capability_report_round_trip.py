"""managed-thing-capability-report-round-trip."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-thing-capability-report-round-trip"
GROUP = "data-plane"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A managed thing created with a CapabilityReport exposes it via
    GetManagedThingCapabilities; one created without a report has none (ResourceNotFoundException)."""
    iot = _iot_client(ctx)

    with_report = iot.create_managed_thing(
        Role="DEVICE",
        AuthenticationMaterial=_wifi_barcode(),
        AuthenticationMaterialType="WIFI_SETUP_QR_BAR_CODE",
        CapabilityReport={"version": "1.0.0", "endpoints": []},
        Tags={"sim2real": "true"},
    )
    with_report_id = with_report["Id"]
    ctx.on_cleanup(lambda: _delete_thing_ignore_missing(iot, with_report_id))

    got = iot.get_managed_thing_capabilities(Identifier=with_report_id)
    version = got["CapabilityReport"]["version"]
    assert version == "1.0.0", f"expected CapabilityReport.version '1.0.0', got {version!r}"
    endpoints = got["CapabilityReport"]["endpoints"]
    assert endpoints == [], f"expected CapabilityReport.endpoints [], got {endpoints!r}"

    without_report = iot.create_managed_thing(
        Role="DEVICE",
        AuthenticationMaterial=_wifi_barcode(),
        AuthenticationMaterialType="WIFI_SETUP_QR_BAR_CODE",
        Tags={"sim2real": "true"},
    )
    without_report_id = without_report["Id"]
    ctx.on_cleanup(lambda: _delete_thing_ignore_missing(iot, without_report_id))

    code, code_msg = _error(lambda: iot.get_managed_thing_capabilities(Identifier=without_report_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a managed thing with no capability report, got {code!r}"
    )
    assert code_msg == 'Managed Thing capabilities not found', code_msg


def _wifi_barcode() -> str:
    # WIFI_SETUP_QR_BAR_CODE's AuthenticationMaterial is undocumented in the Smithy model.
    # The envelope real AWS accepts is exactly "UPC:<valid UPC-A>;SN:<12-digit serial>" with
    # no trailing separators: a 14-digit serial or a trailing ";;" is rejected with "Serial
    # number has incorrect format or contains invalid characters". Kept unique per call so the two
    # managed things created
    # below do not collide on one serial number.
    return f"UPC:012345678905;SN:{str(uuid.uuid4().int)[:12]}"
def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1; the
    # runner's default region (us-west-2) has no endpoint for it, so on real AWS we
    # pin the client to a supported region via ctx.client's region override, which keeps
    # the leased-account credentials and TLS wiring instead of resolving the ambient
    # chain. On an emulator, keep using ctx.client's single shared endpoint.
    return ctx.client("iot-managed-integrations", region="eu-west-1")
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_thing_ignore_missing(iot, thing_id: str) -> None:
    try:
        iot.delete_managed_thing(Identifier=thing_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
