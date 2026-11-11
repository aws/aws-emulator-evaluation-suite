"""braket-search-devices-invalid-filter-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-search-devices-invalid-filter-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["braket"]

SV1_ARN = "arn:aws:braket:::device/quantum-simulator/amazon/sv1"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SearchDevices rejects an unsupported filter name; the same call with a valid name still works."""
    braket = ctx.client("braket")

    err = _client_error(
        lambda: braket.search_devices(filters=[{"name": "notARealFilterName", "values": ["x"]}])
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    expected = "{'filters': [{0: [{'name': ['unallowed value notARealFilterName']}]}]}"
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # Positive control: the only currently-supported filter name is "deviceArn" -- the same
    # operation must still succeed when given a filter it actually understands.
    resp = braket.search_devices(filters=[{"name": "deviceArn", "values": [SV1_ARN]}])
    assert "devices" in resp and isinstance(resp["devices"], list), (
        f"expected a well-formed SearchDevices response with a 'devices' list, got {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
