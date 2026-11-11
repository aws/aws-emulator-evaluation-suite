"""op-contract-describe-vpc-endpoint-services."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-vpc-endpoint-services"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpcEndpointServices resolves the always-present regional S3 gateway service and
    rejects DryRun.
    """
    ec2 = ctx.client("ec2")
    s3_service_name = f"com.amazonaws.{ctx.region}.s3"

    resp = ec2.describe_vpc_endpoint_services(ServiceNames=[s3_service_name])
    details = resp["ServiceDetails"]
    assert len(details) >= 1, f"expected at least 1 ServiceDetail for {s3_service_name}, got 0"
    matching = [d for d in details if d["ServiceName"] == s3_service_name]
    assert matching, f"{s3_service_name} not found in ServiceDetails"
    # S3 can expose both a Gateway and an Interface variant under the very same ServiceName,
    # as separate ServiceDetails entries -- don't assume the first match is the Gateway one.
    gateway_entries = [
        d for d in matching if any(t["ServiceType"] == "Gateway" for t in d["ServiceType"])
    ]
    assert gateway_entries, f"no Gateway-typed entry for {s3_service_name} in {matching}"
    entry = gateway_entries[0]
    assert entry["Owner"] == "amazon", f"expected Owner amazon, got {entry['Owner']!r}"
    assert any(t["ServiceType"] == "Gateway" for t in entry["ServiceType"]), (
        f"expected a Gateway ServiceType in {entry['ServiceType']}"
    )

    code, message = _error(lambda: ec2.describe_vpc_endpoint_services(DryRun=True))
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
