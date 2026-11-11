"""create-vpc-link-invalid-subnet-bad-request."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-vpc-link-invalid-subnet-bad-request"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcLink with a well-formed but nonexistent subnet ID returns BadRequestException
    rather than succeeding or hanging -- no VpcLinkId is ever allocated for the failed
    attempt -- while a real subnet in a throwaway VPC still lets a VPC link be created."""
    apigw = ctx.client("apigatewayv2")
    ec2 = ctx.client("ec2")

    bogus_name = ctx.unique_name("sim2real-behav-vpclink-bad-")
    bogus_subnet_id = "subnet-0000000000bad0bad"
    code, message = _error_code(
        lambda: apigw.create_vpc_link(Name=bogus_name, SubnetIds=[bogus_subnet_id])
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}: {message!r}"
    # AWS relays EC2's error text, which embeds a per-call EC2 Request ID: mask only that id.
    assert re.sub(r"Request ID: [0-9a-f-]+;", "Request ID: <id>;", message or "") == (
        f"The subnet ID '{bogus_subnet_id}' does not exist (Service: AmazonEC2; Status Code: 400; "
        "Error Code: InvalidSubnetID.NotFound; Request ID: <id>; Proxy: null)"
    ), f"BadRequestException message {message!r}"

    # Effect absent: no VPC link with that name was created despite the failed attempt.
    links = apigw.get_vpc_links()["Items"]
    assert not any(link["Name"] == bogus_name for link in links), (
        f"expected no VpcLink named {bogus_name!r} after the rejected CreateVpcLink call, "
        f"found one among {[link['Name'] for link in links]!r}"
    )

    # Positive control: a real subnet (in a throwaway VPC we create ourselves, so this does
    # not depend on the account having a default VPC) lets VPC link creation succeed.
    real_subnet_id, real_sg_id = _create_throwaway_subnet(ctx, ec2)
    good_name = ctx.unique_name("sim2real-behav-vpclink-good-")
    created = _retry_throttled(
        lambda: apigw.create_vpc_link(
            Name=good_name,
            SubnetIds=[real_subnet_id],
            SecurityGroupIds=[real_sg_id],
            Tags={"Name": good_name},
        )
    )
    vpc_link_id = created["VpcLinkId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_vpc_link(VpcLinkId=vpc_link_id)))
    assert created["Name"] == good_name, f"expected VpcLink name {good_name!r}, got {created['Name']!r}"

    _wait_for_vpc_link_available(apigw, vpc_link_id)


def _create_throwaway_subnet(ctx, ec2):
    """Positive-control network for CreateVpcLink: adopt an existing subnet + security
    group if the account already has one (so the check does not add to VPC-quota
    pressure in a shared account), else stand up a minimal throwaway VPC + subnet +
    security group -- so the check does not depend on the account having a default VPC
    either."""
    adopted = _adopt_existing_subnet_and_sg(ec2, ctx=ctx)
    if adopted is not None:
        return adopted

    vpc_name = ctx.unique_name("sim2real-behav-vpclink-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    az_name = azs[0]["ZoneName"]
    subnet_name = ctx.unique_name("sim2real-behav-vpclink-subnet-")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.0.0/25",
        AvailabilityZone=az_name,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    sg_name = ctx.unique_name("sim2real-behav-vpclink-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real behavioral probe sg for CreateVpcLink",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ec2.delete_security_group(GroupId=sg_id)))

    return subnet_id, sg_id


def _adopt_existing_subnet_and_sg(ec2, *, ctx):
    """Any existing subnet with a security group in its own VPC is a fine positive
    control -- CreateVpcLink only needs valid, resolvable ids. Returns None (never
    partially adopts) when the account has no subnet at all, so the caller falls back
    to creating a throwaway VPC."""
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        return None
    subnet = subnets[0]
    subnet_id = subnet["SubnetId"]
    vpc_id = subnet["VpcId"]
    sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get(
        "SecurityGroups", []
    )
    if not sgs:
        return None
    return subnet_id, sgs[0]["GroupId"]


def _wait_for_vpc_link_available(apigw, vpc_link_id, timeout_s: float = 240.0):
    """Bounded poll: a freshly created VPC link eventually reaches AVAILABLE (or FAILED)."""
    import time

    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        got = apigw.get_vpc_link(VpcLinkId=vpc_link_id)
        last_status = got["VpcLinkStatus"]
        if last_status in ("AVAILABLE", "FAILED"):
            assert last_status == "AVAILABLE", f"VPC link ended in status {last_status!r}"
            return
        time.sleep(2)
    raise AssertionError(f"VPC link did not reach AVAILABLE within {timeout_s}s, last status {last_status!r}")


def _error_code(fn):
    import time

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            if code in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, message
        else:
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    raise AssertionError("unreachable")


def _retry_throttled(fn, *, attempts: int = 6, base_delay: float = 3.0):
    import time

    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException") and attempt < attempts - 1:
                last_exc = exc
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise last_exc


def _ignore_not_found(fn) -> None:
    """Teardown: run one delete, tolerating only a not-found answer. A VPC link's ENIs leave the
    subnet and security group minutes after it is deleted, so DependencyViolation (and throttling)
    is retried for 600 s, inside the suite's cleanup budget; anything else raises."""
    import time

    deadline = time.monotonic() + 600
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith("NotFound") or code == "NotFoundException":
                return
            if code not in ("DependencyViolation", "TooManyRequestsException"):
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
