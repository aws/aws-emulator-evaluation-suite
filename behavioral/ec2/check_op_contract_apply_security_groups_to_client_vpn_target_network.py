"""op-contract-applySecurityGroupsToClientVpnTargetNetwork."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-applySecurityGroupsToClientVpnTargetNetwork"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ApplySecurityGroupsToClientVpnTargetNetwork with DryRun on a real VPC/security-group pair answers the
    permission check before resolving the endpoint, and without DryRun a nonexistent endpoint id is
    InvalidClientVpnEndpointId.NotFound; both error responses carry a Message and a RequestId."""
    ec2 = ctx.client("ec2")

    # Reuse the account's permanent default VPC as scaffolding for the
    # security group rather than unconditionally allocating a brand-new
    # dedicated VPC: the account-wide VPC quota is scarce and shared with
    # every other concurrently-running check, and this check has no need
    # of a VPC with any particular property of its own -- it only needs
    # *a* VPC to create a security group in. Only fall back to creating a
    # dedicated VPC if the account has no default VPC.
    vpc_id = _get_default_vpc_id(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_id = _create_vpc_with_retry(
            ec2,
            CidrBlock="10.231.0.0/16",
            TagSpecifications=[
                {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
            ],
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_vpc_and_wait(ec2, vpc_id))
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real behavioral check sg",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-sg-")}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))

    fake_endpoint_id = "cvpn-endpoint-0123456789abcdef0"

    info = _client_error(
        lambda: ec2.apply_security_groups_to_client_vpn_target_network(
            ClientVpnEndpointId=fake_endpoint_id,
            VpcId=vpc_id,
            SecurityGroupIds=[sg_id],
            DryRun=True,
        )
    )
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == "Request would have succeeded, but DryRun flag is set.", (
        f"DryRunOperation message: {info['message']!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    info2 = _client_error(
        lambda: ec2.apply_security_groups_to_client_vpn_target_network(
            ClientVpnEndpointId=fake_endpoint_id,
            VpcId=vpc_id,
            SecurityGroupIds=[sg_id],
        )
    )
    assert info2["code"] == "InvalidClientVpnEndpointId.NotFound", (
        f"expected InvalidClientVpnEndpointId.NotFound, got {info2['code']!r}"
    )
    assert info2["message"] == f"Endpoint {fake_endpoint_id} does not exist", (
        f"InvalidClientVpnEndpointId.NotFound message: {info2['message']!r}"
    )
    assert info2["request_id"], "expected a RequestId in ResponseMetadata"


# ===== helpers =====
def _get_default_vpc_id(ec2, *, ctx):
    """Look up the run's shared network, if any. The shared network is a
    permanent, account-level resource that no check (this one or any
    other concurrently-running one) ever creates or tears down, so it is
    safe scaffolding to reuse without racing anyone else's cleanup."""
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None


def _create_vpc_with_retry(ec2, *, timeout_s: float = 1500.0, interval_s: float = 20.0, **kwargs):
    """CreateVpc can transiently report VpcLimitExceeded while other
    concurrently-running checks in the same account are still holding VPCs
    (the account-wide VPC quota is shared across everything running right
    now, not just recently-deleted VPCs); poll within a bounded window
    instead of treating that as a hard failure. The window is kept well
    inside this check's own overall execution budget so a single retry
    helper invocation can never by itself exhaust the check's total time
    budget."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _client_error(fn):
    """Call fn(); return its error code/message/RequestId. An unexpected SUCCESS raises,
    because ACCEPTING input real AWS refuses is its own failure, not an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {
            "code": err["Code"],
            "message": err.get("Message"),
            "request_id": exc.response.get("ResponseMetadata", {}).get("RequestId"),
        }
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
