"""op-contract-applySecurityGroupsToClientVpnTargetNetwork-b."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-applySecurityGroupsToClientVpnTargetNetwork-b"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ApplySecurityGroupsToClientVpnTargetNetwork on a nonexistent endpoint with a real VPC and group
    fails DryRunOperation with DryRun and InvalidClientVpnEndpointId.NotFound without it, each with its
    exact message and a RequestId.
    """
    ec2 = ctx.client("ec2")

    # The security group goes into the run's network VPC; the check creates its own VPC only
    # when that one does not describe.
    vpc_id = _get_default_vpc_id(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_name = ctx.unique_name("sim2real-behav-vpc-")
        vpc_id = _create_vpc_with_retry(
            ec2,
            CidrBlock="10.233.0.0/16",
            TagSpecifications=[
                {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}
            ],
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_vpc_and_wait(ec2, vpc_id))
    sg_name = ctx.unique_name("sim2real-behav-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real behavioral check sg (second instance)",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))

    fake_endpoint_id = "cvpn-endpoint-0fedcba987654321f"

    info = _client_error_info(
        lambda: ec2.apply_security_groups_to_client_vpn_target_network(
            ClientVpnEndpointId=fake_endpoint_id,
            VpcId=vpc_id,
            SecurityGroupIds=[sg_id],
            DryRun=True,
        )
    )
    assert info is not None, "expected a ClientError (DryRunOperation), call succeeded"
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message {info['message']!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    info2 = _client_error_info(
        lambda: ec2.apply_security_groups_to_client_vpn_target_network(
            ClientVpnEndpointId=fake_endpoint_id,
            VpcId=vpc_id,
            SecurityGroupIds=[sg_id],
        )
    )
    assert info2 is not None, "expected a ClientError (InvalidClientVpnEndpointId.NotFound), call succeeded"
    assert info2["code"] == "InvalidClientVpnEndpointId.NotFound", (
        f"expected InvalidClientVpnEndpointId.NotFound, got {info2['code']!r}"
    )
    assert info2["message"] == f"Endpoint {fake_endpoint_id} does not exist", (
        f"unexpected InvalidClientVpnEndpointId.NotFound message {info2['message']!r}"
    )
    assert info2["request_id"], "expected a RequestId in ResponseMetadata"


# ===== helpers =====
def _get_default_vpc_id(ec2, *, ctx):
    """The VPC id of the run's network, or None when it does not describe."""
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None


def _create_vpc_with_retry(ec2, *, timeout_s: float = 1500.0, interval_s: float = 20.0, **kwargs):
    """CreateVpc, retrying VpcLimitExceeded within a bounded window while VPCs are released."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _client_error_info(fn):
    """The code, message and request id of the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {
            "code": err["Code"],
            "message": err.get("Message"),
            "request_id": exc.response.get("ResponseMetadata", {}).get("RequestId"),
        }
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _delete_vpc_and_wait(ec2, vpc_id: str, *, timeout_s: float = 90.0, interval_s: float = 2.0) -> None:
    """Delete the VPC, retrying only DependencyViolation while a just-deleted dependent's ENIs and
    route tables are released, and wait until DescribeVpcs stops returning it; raise anything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            ec2.describe_vpcs(VpcIds=[vpc_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"vpc {vpc_id} still describes {timeout_s}s after DeleteVpc")
        time.sleep(interval_s)


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
