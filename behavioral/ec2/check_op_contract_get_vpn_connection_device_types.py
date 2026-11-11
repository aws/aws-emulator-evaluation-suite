"""op-contract-get-vpn-connection-device-types."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-vpn-connection-device-types"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVpnConnectionDeviceTypes returns a non-empty catalog whose entries carry the documented fields;
    an out-of-range MaxResults sent past client-side validation fails with InvalidMaxResults and the
    exact message "MaxResults must be greater than 200."."""
    ec2 = ctx.client("ec2")

    resp = ec2.get_vpn_connection_device_types()
    device_types = resp.get("VpnConnectionDeviceTypes", [])
    assert len(device_types) > 0, "expected at least one VPN connection device type"
    first = device_types[0]
    for field in ("VpnConnectionDeviceTypeId", "Vendor", "Platform", "Software"):
        assert field in first, f"expected {field!r} in a VpnConnectionDeviceType, got keys {list(first)}"

    raw = _raw_client_no_validation(ctx, "ec2")

    # Positive control on the same (unvalidated) wiring: an in-range MaxResults succeeds.
    control = raw.get_vpn_connection_device_types(MaxResults=200)
    assert "VpnConnectionDeviceTypes" in control, f"expected VpnConnectionDeviceTypes in {list(control)}"

    # Break exactly one thing: MaxResults below the documented 200-1000 range.
    code, message = _error(lambda: raw.get_vpn_connection_device_types(MaxResults=1))
    assert code == "InvalidMaxResults", f"expected InvalidMaxResults, got {code!r}"
    assert message == "MaxResults must be greater than 200.", (
        f"unexpected error for out-of-range MaxResults: {message!r}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the out-of-range MaxResults to be rejected, but it succeeded")


def _raw_client_no_validation(ctx, service):
    return ctx.client(service, config=Config(parameter_validation=False))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

