"""op-contract-modify-vpc-endpoint-notfound-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-modify-vpc-endpoint-notfound-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcEndpoint replaces a gateway endpoint's policy document, which DescribeVpcEndpoints
    then returns; an unknown VpcEndpointId fails with InvalidVpcEndpointId.NotFound and its exact
    message."""
    ec2 = ctx.client("ec2")
    region = ctx.region

    vpc_id = ec2.create_vpc(CidrBlock="10.203.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", "vpce-vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    rtb_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=_tag_spec(ctx, "route-table", "vpce-rtb"))[
        "RouteTable"
    ]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rtb_id))

    vpce = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{region}.s3",
        VpcEndpointType="Gateway",
        RouteTableIds=[rtb_id],
        TagSpecifications=_tag_spec(ctx, "vpc-endpoint", "vpce-s3"),
    )["VpcEndpoint"]
    vpce_id = vpce["VpcEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]))

    state = _poll_until(
        lambda: _describe_endpoint(ec2, vpce_id),
        lambda e: e is not None and e.get("State") == "available",
        timeout_s=90,
        interval_s=5,
        description="vpc endpoint reaches available",
    )
    assert state["State"] == "available", state

    # error boundary: a syntactically valid but nonexistent endpoint ID.
    err, message = _error(
        lambda: ec2.modify_vpc_endpoint(
            VpcEndpointId="vpce-00000000000000000", PolicyDocument=json.dumps(_deny_all_policy())
        )
    )
    assert err == "InvalidVpcEndpointId.NotFound", err
    assert message == "The Vpc Endpoint Id 'vpce-00000000000000000' does not exist", message

    # success path: attach a restrictive policy and observe it via Describe.
    restrictive_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::sim2real-behav-*/*"],
            }
        ],
    }
    resp = ec2.modify_vpc_endpoint(VpcEndpointId=vpce_id, PolicyDocument=json.dumps(restrictive_policy))
    assert resp["Return"] is True, resp

    updated = _poll_until(
        lambda: _describe_endpoint(ec2, vpce_id),
        lambda e: e is not None and "s3:GetObject" in e.get("PolicyDocument", ""),
        timeout_s=60,
        interval_s=5,
        description="policy document reflects the modified action",
    )
    policy = json.loads(updated["PolicyDocument"])
    actions = policy["Statement"][0]["Action"]
    # Real AWS normalizes a single-element policy Action list to a bare string
    # when it echoes the document back; normalize before comparing so the
    # assertion still pins the exact action set, independent of representation.
    if isinstance(actions, str):
        actions = [actions]
    assert actions == ["s3:GetObject"], policy


def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _deny_all_policy():
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*"}]}


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _describe_endpoint(ec2, vpce_id):
    resp = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])
    items = resp.get("VpcEndpoints", [])
    return items[0] if items else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
