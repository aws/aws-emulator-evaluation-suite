"""op-contract-describe-route-servers."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-route-servers"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeRouteServers: success contract returns the documented list
    shape; DryRun=True rejects with DryRunOperation."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_route_servers()
    assert "RouteServers" in resp, f"missing RouteServers key in response: {resp!r}"
    assert isinstance(resp["RouteServers"], list), (
        f"expected RouteServers to be a list, got {type(resp['RouteServers'])!r}"
    )

    code, msg = _client_error(lambda: ec2.describe_route_servers(DryRun=True))
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
