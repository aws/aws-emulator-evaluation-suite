"""op-contract-create-vpc."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-vpc"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpc with DryRun answers DryRunOperation and creates nothing; the real call yields an
    available VPC with its CIDR associated and one main route table, network ACL and security group;
    after delete, describe and delete of the ID fail with InvalidVpcID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    cidr = "10.201.0.0/16"
    name = ctx.unique_name("sim2real-behav-vpc-")

    # --- error boundary: DryRun must fail with DryRunOperation and create nothing ---
    code, message = _error(lambda: ec2.create_vpc(CidrBlock=cidr, DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    before = ec2.describe_vpcs(Filters=[{"Name": "cidr-block", "Values": [cidr]}])["Vpcs"]
    assert before == [], f"DryRun must not create a VPC, found {before}"

    # --- success path ---
    resp = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc = resp["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ctx, vpc_id))
    assert vpc["CidrBlock"] == cidr, f"expected CidrBlock {cidr}, got {vpc['CidrBlock']}"
    assert vpc["InstanceTenancy"] == "default", f"expected default tenancy, got {vpc['InstanceTenancy']}"
    assert vpc["State"] in ("pending", "available"), f"expected pending/available, got {vpc['State']}"

    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    described = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    assert described["State"] == "available", f"expected available, got {described['State']}"
    cidr_state = described["CidrBlockAssociationSet"][0]["CidrBlockState"]["State"]
    assert cidr_state == "associated", f"expected associated, got {cidr_state}"

    # a fresh VPC always comes with an implicit main route table and default NACL/SG
    route_tables = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "association.main", "Values": ["true"]}]
    )["RouteTables"]
    assert len(route_tables) == 1, f"expected 1 implicit main route table, got {len(route_tables)}"

    nacls = ec2.describe_network_acls(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "default", "Values": ["true"]}]
    )["NetworkAcls"]
    assert len(nacls) == 1, f"expected 1 default network ACL, got {len(nacls)}"

    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    assert len(sgs) == 1, f"expected 1 default security group, got {len(sgs)}"

    # --- delete proves gone and unusable: independent read 404s, and a further
    # mutation on the dead id is rejected with the same specific not-found code ---
    ec2.delete_vpc(VpcId=vpc_id)
    gone_code, gone_message = _error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]))
    assert gone_code == "InvalidVpcID.NotFound", f"expected InvalidVpcID.NotFound after delete, got {gone_code}"
    assert gone_message == f"The vpc ID '{vpc_id}' does not exist", f"unexpected InvalidVpcID.NotFound message {gone_message!r}"
    dead_code, dead_message = _error(lambda: ec2.delete_vpc(VpcId=vpc_id))
    assert dead_code == "InvalidVpcID.NotFound", f"expected InvalidVpcID.NotFound on dead id, got {dead_code}"
    assert dead_message == f"The vpc ID '{vpc_id}' does not exist", f"unexpected InvalidVpcID.NotFound message {dead_message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_vpc(ctx, vpc_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
