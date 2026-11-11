"""braket-search-devices-filters-by-device-arn."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "braket-search-devices-filters-by-device-arn"
GROUP = "data-plane"
SERVICES = ["braket"]

SV1_ARN = "arn:aws:braket:::device/quantum-simulator/amazon/sv1"


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchDevices filtered by deviceArn returns exactly the one matching device."""
    braket = ctx.client("braket")
    resp = braket.search_devices(filters=[{"name": "deviceArn", "values": [SV1_ARN]}])
    devices = resp["devices"]
    if not devices:
        raise AssertionError(
            f"SV1 simulator device ({SV1_ARN}) is not returned by SearchDevices in region {ctx.region}"
        )
    assert len(devices) == 1, f"expected exactly one match for {SV1_ARN}, got {len(devices)}"
    assert devices[0]["deviceArn"] == SV1_ARN, (
        f"expected deviceArn {SV1_ARN!r}, got {devices[0]['deviceArn']!r}"
    )
    assert devices[0]["deviceType"] == "SIMULATOR", (
        f"expected deviceType 'SIMULATOR', got {devices[0]['deviceType']!r}"
    )
    assert devices[0]["deviceStatus"] == "ONLINE", (
        f"expected deviceStatus 'ONLINE', got {devices[0]['deviceStatus']!r}"
    )
    assert devices[0]["providerName"] == "Amazon Braket", (
        f"expected providerName 'Amazon Braket', got {devices[0]['providerName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
