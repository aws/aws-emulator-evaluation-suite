"""vpc-endpoint-gateway-create-reject-bad-service."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call *fn*; return the AWS error (code, message). Raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


CHECK = "vpc-endpoint-gateway-create-reject-bad-service"
GROUP = 'vpc-networking'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcEndpoint (gateway type) reaches available; bad service name is rejected."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.103.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda state: state == "available",
        timeout_s=60,
        description="vpc available",
    )

    service_name = f"com.amazonaws.{ctx.region}.s3"

    bad_service = f"com.amazonaws.{ctx.region}.not-a-real-service"
    bad, bad_message = _error(
        lambda: ec2.create_vpc_endpoint(VpcId=vpc_id, ServiceName=bad_service)
    )
    assert bad == "InvalidServiceName", f"expected InvalidServiceName, got {bad}"
    expected_bad = f"The Vpc Endpoint Service '{bad_service}' does not exist"
    assert bad_message == expected_bad, f"expected message {expected_bad!r}, got {bad_message!r}"

    resp = ec2.create_vpc_endpoint(
        VpcId=vpc_id, ServiceName=service_name, VpcEndpointType="Gateway",
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    ep = resp["VpcEndpoint"]
    ep_id = ep["VpcEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[ep_id]))
    assert ep["VpcEndpointType"] == "Gateway", f"expected Gateway, got {ep['VpcEndpointType']}"
    assert ep["ServiceName"] == service_name, f"expected {service_name}, got {ep['ServiceName']}"

    # independent read: the create call's own response is not the terminal assertion — confirm
    # the endpoint actually reaches "available" via a fresh describe, at both endpoints
    endpoint = _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[ep_id])["VpcEndpoints"][0],
        lambda e: e["State"] == "available",
        timeout_s=180,
        description="vpc endpoint available",
    )
    assert endpoint["VpcId"] == vpc_id, f"expected {vpc_id}, got {endpoint['VpcId']}"
    assert endpoint["ServiceName"] == service_name, f"expected {service_name}, got {endpoint['ServiceName']}"

    result = ec2.delete_vpc_endpoints(VpcEndpointIds=[ep_id])
    assert result.get("Unsuccessful") == [], f"delete reported failures: {result}"

    # independent read: the delete's own response is not enough either -- confirm the endpoint is
    # actually gone (real AWS keeps a deleted id describable in state "deleted" for a while before
    # it stops recognizing the id at all), and that a mutation on it now fails.
    def _probe_gone():
        try:
            described = ec2.describe_vpc_endpoints(VpcEndpointIds=[ep_id])["VpcEndpoints"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpcEndpointId.NotFound":
                return "gone"
            raise
        return described[0]["State"] if described else "gone"

    _poll_until(
        _probe_gone,
        lambda s: s in ("deleted", "gone"),
        timeout_s=60,
        description="vpc endpoint deleted",
    )

    modify_code, modify_message = _error(
        lambda: ec2.modify_vpc_endpoint(
            VpcEndpointId=ep_id,
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}
            ),
        )
    )
    assert modify_code == "InvalidVpcEndpointId.NotFound", (
        f"expected the deleted endpoint id to be unusable, got {modify_code}"
    )
    expected_modify = f"The Vpc Endpoint Id '{ep_id}' does not exist"
    assert modify_message == expected_modify, (
        f"expected message {expected_modify!r}, got {modify_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
