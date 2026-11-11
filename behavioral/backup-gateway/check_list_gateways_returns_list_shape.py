"""list-gateways-returns-list-shape."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-gateways-returns-list-shape"
GROUP = "smoke"
SERVICES = ["backup-gateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGateways returns a well-formed Gateways list, and a NextToken it never issued is rejected
    with ValidationException and its exact message."""
    bg = ctx.client("backup-gateway")

    resp = bg.list_gateways()
    gateways = resp.get("Gateways")
    assert isinstance(gateways, list), f"expected Gateways to be a list, got {gateways!r}"
    for gw in gateways:
        assert "GatewayArn" in gw, f"gateway entry missing GatewayArn: {gw!r}"
        assert "GatewayDisplayName" in gw, f"gateway entry missing GatewayDisplayName: {gw!r}"

    # A NextToken ListGateways never issued (valid per the model's pattern and length, so the
    # client sends it) is rejected by the service.
    got = _client_error(lambda: bg.list_gateways(NextToken="sim2real-not-a-real-continuation-token"))
    expected = ("ValidationException", "The pagination token is invalid and cannot be processed.")
    assert got == expected, f"expected {expected!r} for a fabricated NextToken, got {got!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
