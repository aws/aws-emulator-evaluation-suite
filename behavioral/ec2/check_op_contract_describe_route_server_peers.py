"""op-contract-describe-route-server-peers."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-route-server-peers"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeRouteServerPeers: success contract returns the documented
    list shape; DryRun=True rejects with DryRunOperation."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_route_server_peers()
    assert "RouteServerPeers" in resp, f"response missing RouteServerPeers: {resp!r}"
    assert isinstance(resp["RouteServerPeers"], list), (
        f"RouteServerPeers is not a list: {resp['RouteServerPeers']!r}"
    )

    code, msg = _client_error(lambda: ec2.describe_route_server_peers(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
