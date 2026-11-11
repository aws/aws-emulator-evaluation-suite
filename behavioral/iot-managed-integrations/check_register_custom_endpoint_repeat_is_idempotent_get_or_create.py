"""register-custom-endpoint-repeat-is-idempotent-get-or-create."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-custom-endpoint-repeat-is-idempotent-get-or-create"
GROUP = "overly-permissive"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterCustomEndpoint is an idempotent get-or-create for the account's custom endpoint.

    A repeat call succeeds and returns the IDENTICAL EndpointAddress (never ConflictException),
    and GetCustomEndpoint keeps reporting that same address."""
    iot = _iot_client(ctx)

    first_register = iot.register_custom_endpoint()["EndpointAddress"]
    assert first_register, "RegisterCustomEndpoint returned no EndpointAddress"

    first_read = iot.get_custom_endpoint()["EndpointAddress"]
    assert first_read == first_register, (
        f"GetCustomEndpoint address {first_read!r} != the one RegisterCustomEndpoint just "
        f"returned {first_register!r}"
    )

    # Positive control: the endpoint address is stable across repeated reads.
    second_read = iot.get_custom_endpoint()["EndpointAddress"]
    assert second_read == first_read, (
        f"expected GetCustomEndpoint to be stable, got {first_read!r} then {second_read!r}"
    )

    # RegisterCustomEndpoint is idempotent: a further call succeeds and returns the SAME
    # address rather than minting a new one.
    second_register = iot.register_custom_endpoint()["EndpointAddress"]
    assert second_register == first_register, (
        f"expected the repeat RegisterCustomEndpoint to be idempotent, got "
        f"{first_register!r} then {second_register!r}"
    )

    # Effect absent: the repeat call did not change the address at the destination.
    third_read = iot.get_custom_endpoint()["EndpointAddress"]
    assert third_read == first_register, (
        f"repeat RegisterCustomEndpoint must not change the address: expected "
        f"{first_register!r}, got {third_read!r}"
    )


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1, so pin the region
    # via ctx.client's `region=` override, which keeps ctx's credentials and endpoint wiring.
    return ctx.client("iot-managed-integrations", region="eu-west-1")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
