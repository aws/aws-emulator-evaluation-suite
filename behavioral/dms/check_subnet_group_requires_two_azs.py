"""subnet-group-requires-two-azs."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "subnet-group-requires-two-azs"
GROUP = 'validation'
SERVICES = ['dms']

_DMS_VPC_ROLE = 'dms-vpc-role'  # AWS fixes this name; subnet groups require it.
_DMS_VPC_POLICY = 'arn:aws:iam::aws:policy/service-role/AmazonDMSVPCManagementRole'
_DMS_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "dms.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _error(fn) -> tuple[str, str]:
    """The exact error code and message real AWS returned, or a failure if it returned success."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 — the code is the subject of the assertion
        response = getattr(exc, 'response', None)
        assert isinstance(response, dict), f"expected a modelled AWS error, got {exc!r}"
        return response['Error']['Code'], response['Error'].get('Message', '')
    raise AssertionError("expected the call to be rejected, but it succeeded")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReplicationSubnetGroup with subnets in one zone fails with ReplicationSubnetGroupDoesNotCoverEnoughAZs
    and its exact message and creates no group, while adding a subnet in a second zone creates a Complete
    group with both subnets and zones: a rule the model's plain SubnetIds list does not encode."""
    dms = ctx.client("dms")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    _ensure_dms_vpc_role(iam)

    vpc_id = ec2.create_vpc(CidrBlock='10.32.0.0/16')['Vpc']['VpcId']
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    region_zones = sorted(z['ZoneName'] for z in ec2.describe_availability_zones(
        Filters=[{'Name': 'state', 'Values': ['available']},
                 {'Name': 'opt-in-status', 'Values': ['opt-in-not-required']}]
    )['AvailabilityZones'])
    zones = region_zones[:2]
    assert len(zones) == 2, f"region {ctx.region} offered {zones}, need two availability zones"

    first = ec2.create_subnet(VpcId=vpc_id, CidrBlock='10.32.1.0/24',
                             AvailabilityZone=zones[0])['Subnet']['SubnetId']
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=first))

    sng = ctx.unique_name("sim2real-behav-dms-sng-")
    description = 'sim2real availability-zone coverage check'

    # A dms-vpc-role created moments ago is refused as AccessDeniedFault until IAM propagates.
    deadline = time.monotonic() + 90
    while True:
        code, message = _error(lambda: dms.create_replication_subnet_group(
            ReplicationSubnetGroupIdentifier=sng,
            ReplicationSubnetGroupDescription=description,
            SubnetIds=[first],
        ))
        if code != 'AccessDeniedFault' or time.monotonic() > deadline:
            break
        time.sleep(5)
    assert code == 'ReplicationSubnetGroupDoesNotCoverEnoughAZs', (
        f"a single-zone subnet group was rejected as {code!r}, expected "
        f"'ReplicationSubnetGroupDoesNotCoverEnoughAZs'"
    )
    assert message == (
        "Replication Subnet Group doesn't meet availability zone coverage requirement. "
        "Please create a subnet group containing subnets to cover at least 2 availability "
        "zones using the DMS console or CLI commands create-replication-subnet-group or "
        "modify-replication-subnet-group. Current AZ coverage: 1. Valid availability zones "
        f"are: [{', '.join(region_zones)}]"
    ), message

    # ...and nothing was stored under that identifier: DMS reports a delete of an absent group
    # as not-found, which it could not do if the refused create had persisted anything.
    absent_code, absent_message = _error(lambda: dms.delete_replication_subnet_group(
        ReplicationSubnetGroupIdentifier=sng
    ))
    assert absent_code == 'ResourceNotFoundFault', (
        f"deleting the refused subnet group {sng!r} gave {absent_code!r}, expected "
        f"'ResourceNotFoundFault' — a refused create must leave no group behind"
    )
    assert absent_message == f"Replication Subnet Group '{sng}' does not exist.", absent_message

    # Positive control: one more subnet, in a second zone, and the identical request is accepted.
    second = ec2.create_subnet(VpcId=vpc_id, CidrBlock='10.32.2.0/24',
                              AvailabilityZone=zones[1])['Subnet']['SubnetId']
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=second))

    group = dms.create_replication_subnet_group(
        ReplicationSubnetGroupIdentifier=sng,
        ReplicationSubnetGroupDescription=description,
        SubnetIds=[first, second],
    )['ReplicationSubnetGroup']
    ctx.on_cleanup(
        lambda: dms.delete_replication_subnet_group(ReplicationSubnetGroupIdentifier=sng)
    )
    assert group['SubnetGroupStatus'] == 'Complete', (
        f"the accepted subnet group reports status {group['SubnetGroupStatus']!r}, expected "
        f"'Complete'"
    )
    assert group['VpcId'] == vpc_id, (
        f"the accepted subnet group reports VpcId {group['VpcId']!r}, expected {vpc_id!r}"
    )
    assert {s['SubnetIdentifier'] for s in group['Subnets']} == {first, second}, (
        f"the accepted subnet group holds "
        f"{sorted(s['SubnetIdentifier'] for s in group['Subnets'])!r}, expected both subnets"
    )
    assert {s['SubnetAvailabilityZone']['Name'] for s in group['Subnets']} == set(zones), (
        f"the accepted subnet group spans "
        f"{sorted(s['SubnetAvailabilityZone']['Name'] for s in group['Subnets'])!r}, expected "
        f"the two zones {zones!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
