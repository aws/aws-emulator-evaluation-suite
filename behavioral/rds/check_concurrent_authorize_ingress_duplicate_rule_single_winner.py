"""concurrent-authorize-ingress-duplicate-rule-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-authorize-ingress-duplicate-rule-single-winner"
GROUP = "concurrency"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent AuthorizeDBSecurityGroupIngress calls on a VPC DB security group both fail with
    the same InvalidParameterValue message (VPC groups refuse every mutation) and add no
    EC2SecurityGroups entry; an unrelated CreateDBParameterGroup succeeds as a control."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    sg_name = ctx.unique_name("sim2real-ec2sg-")
    sg = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real concurrent ingress race target",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    group_name = ctx.unique_name("sim2real-dbsg-")
    rds.create_db_security_group(
        DBSecurityGroupName=group_name,
        DBSecurityGroupDescription="sim2real concurrent ingress race",
    )
    ctx.on_cleanup(lambda: rds.delete_db_security_group(DBSecurityGroupName=group_name))

    def _authorize():
        try:
            rds.authorize_db_security_group_ingress(
                DBSecurityGroupName=group_name,
                EC2SecurityGroupId=sg_id,
            )
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(
            "AuthorizeDBSecurityGroupIngress on a VPC DB security group succeeded; "
            "expected a rejection"
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _authorize(), range(2)))

    # Both concurrent callers must fail identically: no winner, no asymmetric outcome.
    vpc_blocked = (
        "InvalidParameterValue",
        "VPC DB Security Groups cannot be modified with this API version.  Please use an "
        "API version between 2012-01-15 and 2012-10-31 to modify this group.",
    )
    assert len(results) == 2 and results[0] == vpc_blocked and results[1] == vpc_blocked, (
        f"expected both concurrent calls to be deterministically rejected identically, got "
        f"results={results}"
    )

    # No EC2SecurityGroup entry was created by either call -- effect absent on both sides.
    groups = rds.describe_db_security_groups(DBSecurityGroupName=group_name)["DBSecurityGroups"]
    assert len(groups) == 1, f"expected exactly one DB security group, got {len(groups)}"
    ec2_sgs = groups[0]["EC2SecurityGroups"]
    matching = [g for g in ec2_sgs if g["EC2SecurityGroupId"] == sg_id]
    assert not matching, (
        f"both AuthorizeDBSecurityGroupIngress calls were rejected but an EC2SecurityGroup "
        f"entry was created anyway: {matching}"
    )

    # Control: an unrelated create call succeeds normally.
    pg_name = ctx.unique_name("sim2real-dbpg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily="postgres16",
        Description="sim2real concurrent-ingress positive control",
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))
    created = rds.describe_db_parameter_groups(DBParameterGroupName=pg_name)["DBParameterGroups"]
    assert len(created) == 1 and created[0]["DBParameterGroupName"] == pg_name, (
        f"expected the positive-control parameter group {pg_name!r} to exist, got {created!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
