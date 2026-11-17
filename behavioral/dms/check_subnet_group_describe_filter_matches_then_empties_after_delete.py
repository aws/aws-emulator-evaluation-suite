"""subnet-group-describe-filter-matches-then-empties-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-group-describe-filter-matches-then-empties-after-delete"
GROUP = "representation"
SERVICES = ["dms"]

_DMS_VPC_ROLE = "dms-vpc-role"  # AWS fixes this name; subnet groups require it.
_DMS_VPC_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonDMSVPCManagementRole"
_DMS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "dms.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_NOT_FOUND = "ResourceNotFoundFault"


def _ensure_dms_vpc_role(iam) -> None:
    """Create the fixed-name service role DMS needs to read our VPC, if absent. The name is not
    ours to randomize, so this is create-if-absent and deliberately NOT torn down: deleting an
    account-global prerequisite out from under a sibling run is worse than leaving it."""
    try:
        iam.get_role(RoleName=_DMS_VPC_ROLE)
        return
    except iam.exceptions.NoSuchEntityException:
        pass
    iam.create_role(RoleName=_DMS_VPC_ROLE, AssumeRolePolicyDocument=json.dumps(_DMS_TRUST))
    iam.attach_role_policy(RoleName=_DMS_VPC_ROLE, PolicyArn=_DMS_VPC_POLICY)


def _create_subnet_group_with_retry(dms, **kwargs) -> dict:
    """Retry past the window where dms-vpc-role exists but has not yet propagated to DMS."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return dms.create_replication_subnet_group(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedFault" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own
    not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A replication subnet group's identifier, description, VpcId, status and both
    subnets/AZs read back exactly through a filtered describe, the group also appears in
    an unfiltered walk, and the filtered describe answers an empty list once it is deleted.
    """
    dms = ctx.client("dms")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")

    _ensure_dms_vpc_role(iam)

    vpc_id = ec2.create_vpc(CidrBlock="10.78.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real", "Value": CHECK}])

    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "opt-in-status", "Values": ["opt-in-not-required"]}]
    )["AvailabilityZones"])[:2]
    assert len(zones) == 2, f"region {ctx.region} offered {zones}, need two availability zones"

    subnet_ids = []
    for i, zone in enumerate(zones):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.78.{i}.0/24", AvailabilityZone=zone
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: ec2.delete_subnet(SubnetId=s))
        subnet_ids.append(subnet_id)

    sng = ctx.unique_name("sim2real-behav-dms-sngd-")
    description = "sim2real subnet group describe-filter lifecycle"

    _create_subnet_group_with_retry(
        dms,
        ReplicationSubnetGroupIdentifier=sng,
        ReplicationSubnetGroupDescription=description,
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(
        lambda: dms.delete_replication_subnet_group(ReplicationSubnetGroupIdentifier=sng),
        _NOT_FOUND,
    ))

    filtered = dms.describe_replication_subnet_groups(
        Filters=[{"Name": "replication-subnet-group-id", "Values": [sng]}],
        MaxRecords=20,
    )["ReplicationSubnetGroups"]
    assert len(filtered) == 1, (
        f"a filtered describe for {sng!r} returned {len(filtered)} group(s), expected exactly 1"
    )
    group = filtered[0]
    assert group["ReplicationSubnetGroupIdentifier"] == sng, (
        f"the filtered group's identifier reads {group['ReplicationSubnetGroupIdentifier']!r}, "
        f"expected {sng!r}"
    )
    assert group["ReplicationSubnetGroupDescription"] == description, (
        f"the filtered group's description reads "
        f"{group['ReplicationSubnetGroupDescription']!r}, expected {description!r}"
    )
    assert group["VpcId"] == vpc_id, (
        f"the filtered group's VpcId reads {group['VpcId']!r}, expected {vpc_id!r}"
    )
    assert group["SubnetGroupStatus"] == "Complete", (
        f"the filtered group's status reads {group['SubnetGroupStatus']!r}, expected 'Complete'"
    )
    assert {s["SubnetIdentifier"] for s in group["Subnets"]} == set(subnet_ids), (
        f"the filtered group holds subnets "
        f"{sorted(s['SubnetIdentifier'] for s in group['Subnets'])!r}, expected both "
        f"{sorted(subnet_ids)!r}"
    )
    assert {s["SubnetAvailabilityZone"]["Name"] for s in group["Subnets"]} == set(zones), (
        f"the filtered group spans zones "
        f"{sorted(s['SubnetAvailabilityZone']['Name'] for s in group['Subnets'])!r}, "
        f"expected {sorted(zones)!r}"
    )

    paginator = dms.get_paginator("describe_replication_subnet_groups")
    walked = [
        g["ReplicationSubnetGroupIdentifier"]
        for page in paginator.paginate(PaginationConfig={"PageSize": 20})
        for g in page["ReplicationSubnetGroups"]
    ]
    assert sng in walked, (
        f"an unfiltered walk of {len(walked)} subnet group(s) did not include {sng!r}"
    )

    dms.delete_replication_subnet_group(ReplicationSubnetGroupIdentifier=sng)

    after_delete = dms.describe_replication_subnet_groups(
        Filters=[{"Name": "replication-subnet-group-id", "Values": [sng]}],
        MaxRecords=20,
    )["ReplicationSubnetGroups"]
    assert after_delete == [], (
        f"the filtered describe for the deleted group {sng!r} returned {after_delete!r}, "
        f"expected an empty list"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
