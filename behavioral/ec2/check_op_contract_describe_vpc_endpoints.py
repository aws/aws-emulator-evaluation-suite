"""op-contract-describe-vpc-endpoints."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-vpc-endpoints"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpcEndpoints: success returns the created gateway endpoint with correct
    attributes and filters work; a bogus VpcEndpointId is rejected with the specific
    InvalidVpcEndpointId.NotFound error."""
    ec2 = ctx.client("ec2")

    vpc_id = ctx.network().vpc_id

    service_name = f"com.amazonaws.{ctx.region}.s3"
    endpoint = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=service_name,
        VpcEndpointType="Gateway",
        TagSpecifications=_tag_spec(ctx, "vpc-endpoint", ctx.unique_name("sim2real-vpce-")),
    )["VpcEndpoint"]
    endpoint_id = endpoint["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint(ec2, endpoint_id))

    described = _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0],
        lambda ep: ep["State"] == "available",
        timeout_s=60.0,
    )
    assert described["VpcId"] == vpc_id, f"expected VpcId {vpc_id}, got {described['VpcId']}"
    assert described["ServiceName"] == service_name, (
        f"expected ServiceName {service_name}, got {described['ServiceName']}"
    )
    assert described["VpcEndpointType"] == "Gateway", (
        f"expected VpcEndpointType Gateway, got {described['VpcEndpointType']}"
    )

    by_filter = ec2.describe_vpc_endpoints(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "VpcEndpoints"
    ]
    assert any(ep["VpcEndpointId"] == endpoint_id for ep in by_filter), (
        f"expected {endpoint_id} in vpc-id filtered results, "
        f"got {[ep['VpcEndpointId'] for ep in by_filter]}"
    )

    code, message = _error(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=["vpce-00000000000000000"])
    )
    assert code == "InvalidVpcEndpointId.NotFound", (
        f"expected InvalidVpcEndpointId.NotFound for a bogus VpcEndpointId, got {code}"
    )
    assert message == "The Vpc Endpoint Id 'vpce-00000000000000000' does not exist", (
        f"unexpected InvalidVpcEndpointId.NotFound message: {message!r}"
    )

    # the delete this check already performs at cleanup is otherwise unasserted; prove it
    # here instead — an independent DescribeVpcEndpoints read must confirm the endpoint is
    # gone (or in its terminal "deleted" state, matching real AWS's own observed behavior).
    delete_resp = ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id])
    assert delete_resp.get("Unsuccessful") == [], (
        f"expected {endpoint_id} to delete cleanly, got Unsuccessful={delete_resp.get('Unsuccessful')}"
    )

    def _probe_deleted():
        try:
            eps = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]
        except ClientError as exc:
            assert exc.response["Error"]["Code"] == "InvalidVpcEndpointId.NotFound", (
                f"expected InvalidVpcEndpointId.NotFound reading a deleted endpoint, "
                f"got {exc.response['Error']['Code']}"
            )
            assert exc.response["Error"]["Message"] == f"The Vpc Endpoint Id '{endpoint_id}' does not exist", (
                f"unexpected InvalidVpcEndpointId.NotFound message: {exc.response['Error']['Message']!r}"
            )
            return "gone"
        return eps[0]["State"].lower() if eps else "gone"

    _poll_until(_probe_deleted, lambda s: s in ("deleted", "gone"), timeout_s=60.0)


# ===== helpers =====
def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


_ENDPOINT_GONE = frozenset({"InvalidVpcEndpoint.NotFound", "InvalidVpcEndpointId.NotFound"})


def _delete_vpc_endpoint(ec2, endpoint_id):
    """DeleteVpcEndpoints reports per-endpoint failures in Unsuccessful: an endpoint already
    gone is fine, any other failure raises."""
    failed = ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id]).get("Unsuccessful", [])
    if any(f["Error"]["Code"] not in _ENDPOINT_GONE for f in failed):
        raise RuntimeError(f"DeleteVpcEndpoints {endpoint_id} failed: {failed}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
