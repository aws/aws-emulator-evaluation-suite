"""op-contract-describe-vpc-endpoint-connections."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-vpc-endpoint-connections"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpcEndpointConnections returns a well-formed (empty) result for a filter that
    cannot match anything, and rejects DryRun.
    """
    ec2 = ctx.client("ec2")

    resp = ec2.describe_vpc_endpoint_connections(
        Filters=[{"Name": "service-id", "Values": ["vpce-svc-00000000000000000"]}]
    )
    assert "VpcEndpointConnections" in resp, f"expected VpcEndpointConnections key, got {sorted(resp)}"
    assert resp["VpcEndpointConnections"] == [], (
        f"expected no connections for a non-matching filter, got {resp['VpcEndpointConnections']}"
    )

    code, message = _error(lambda: ec2.describe_vpc_endpoint_connections(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
