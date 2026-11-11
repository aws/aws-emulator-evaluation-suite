"""braket-search-devices-no-filters-lists-catalog."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "braket-search-devices-no-filters-lists-catalog"
GROUP = "data-plane"
SERVICES = ["braket"]

_VALID_TYPES = {"QPU", "SIMULATOR"}
_VALID_STATUSES = {"ONLINE", "OFFLINE", "RETIRED"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchDevices with no filters lists the whole device catalog with well-formed entries."""
    braket = ctx.client("braket")
    resp = braket.search_devices(filters=[])
    devices = resp["devices"]
    assert len(devices) >= 1, "expected at least one device in the Braket catalog"

    seen_arns = set()
    for device in devices:
        assert device["deviceArn"] not in seen_arns, f"duplicate deviceArn {device['deviceArn']!r}"
        seen_arns.add(device["deviceArn"])
        assert device["deviceType"] in _VALID_TYPES, f"unexpected deviceType {device['deviceType']!r}"
        assert device["deviceStatus"] in _VALID_STATUSES, (
            f"unexpected deviceStatus {device['deviceStatus']!r}"
        )
        assert device["deviceName"]
        assert device["providerName"]

    # The always-available SV1 on-demand simulator must be part of the unfiltered catalog.
    assert any(
        d["deviceArn"] == "arn:aws:braket:::device/quantum-simulator/amazon/sv1" for d in devices
    ), "SV1 simulator missing from the unfiltered device catalog"

    # An unfiltered catalog is more than Amazon's own on-demand simulators: real hardware
    # providers (D-Wave et al.) must be represented too, or a target that only implements the
    # simulators it can actually execute would pass this check by omission.
    providers = {d["providerName"] for d in devices}
    assert len(providers) > 1, f"expected devices from more than one provider, got {providers!r}"
    assert any(d["deviceType"] == "QPU" for d in devices), (
        "expected at least one QPU device in the unfiltered catalog, got only "
        f"{sorted({d['deviceType'] for d in devices})!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
