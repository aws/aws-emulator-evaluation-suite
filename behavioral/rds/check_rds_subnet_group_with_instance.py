"""rds-subnet-group-with-instance."""
from __future__ import annotations

import time


from behavioral_harness import tags
import secrets

CHECK = "rds-subnet-group-with-instance"
GROUP = 'e2e_workflows'
SERVICES = ['rds']

def _default_db_subnet_ids(ctx, count=2):
    """Return *count* default-VPC subnet ids in distinct AZs for a subnet group."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(
        Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]
    ).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az: dict[str, str] = {}
    for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    ids = [by_az[az] for az in sorted(by_az)][:count]
    if len(ids) < count:
        raise AssertionError(f"shared network has only {len(ids)} usable subnets; need {count}")
    return ids

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """REAL BACKEND: create a DBSubnetGroup from real default-VPC subnets (>=2 AZs),
    launch a db.t3.micro INTO it, wait available, and assert the instance reports
    the subnet group.
    """
    rds = ctx.client("rds")

    subnet_ids = _default_db_subnet_ids(ctx, count=2)
    sng_name = ctx.unique_name("sim2real-behav-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=sng_name,
        DBSubnetGroupDescription="sim2real behavioral subnet group with instance",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _retry_while_held(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=sng_name), "InvalidDBSubnetGroupStateFault", timeout_s=1200.0))

    resp = rds.describe_db_subnet_groups(DBSubnetGroupName=sng_name)
    group = resp["DBSubnetGroups"][0]
    assert group["DBSubnetGroupName"] == sng_name, (
        f"expected subnet group name {sng_name}, got {group['DBSubnetGroupName']!r}"
    )
    got_subnet_ids = {s["SubnetIdentifier"] for s in group["Subnets"]}
    assert got_subnet_ids == set(subnet_ids), (
        f"expected subnet group to hold {set(subnet_ids)}, got {got_subnet_ids}"
    )

    inst_id = ctx.unique_name("sim2real-behav-inst-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        Engine="mysql",
        EngineVersion="8.0",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        BackupRetentionPeriod=0,
        DBSubnetGroupName=sng_name,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True))
    deadline = time.monotonic() + 1500
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=inst_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
        if status == "available":
            break
        time.sleep(2)
    else:
        raise AssertionError(f"DB instance {inst_id} available not met in time")

    inst = rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    reported = inst.get("DBSubnetGroup", {}).get("DBSubnetGroupName")
    assert reported == sng_name, (
        f"instance did not reflect its subnet group: expected {sng_name}, got {reported!r}"
    )


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=15.0):
    """Run a teardown delete, retrying while AWS refuses it because a dependent resource deleted just
    before it is still going away; after the deadline the last refusal is raised."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
