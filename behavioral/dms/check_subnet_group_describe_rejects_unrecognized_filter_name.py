"""subnet-group-describe-rejects-unrecognized-filter-name."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-group-describe-rejects-unrecognized-filter-name"
GROUP = "validation"
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


def _error(fn) -> tuple[str, str]:
    """The exact error code and message real AWS returned, or a failure if it returned success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeReplicationSubnetGroups rejects a Filter.Name it does not recognize with
    its exact message, while the documented replication-subnet-group-id filter still works.
    """
    dms = ctx.client("dms")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")

    _ensure_dms_vpc_role(iam)

    vpc_id = ec2.create_vpc(CidrBlock="10.79.0.0/16")["Vpc"]["VpcId"]
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
            VpcId=vpc_id, CidrBlock=f"10.79.{i}.0/24", AvailabilityZone=zone
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: ec2.delete_subnet(SubnetId=s))
        subnet_ids.append(subnet_id)

    sng = ctx.unique_name("sim2real-behav-dms-sngf-")
    _create_subnet_group_with_retry(
        dms,
        ReplicationSubnetGroupIdentifier=sng,
        ReplicationSubnetGroupDescription="sim2real subnet group filter-name rejection",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(
        lambda: dms.delete_replication_subnet_group(ReplicationSubnetGroupIdentifier=sng),
        _NOT_FOUND,
    ))

    bad_filter_name = "not-a-real-filter"
    code, message = _error(lambda: dms.describe_replication_subnet_groups(
        Filters=[{"Name": bad_filter_name, "Values": [sng]}]
    ))
    assert code == "InvalidParameterValueException", (
        f"an unrecognized filter name was rejected as {code!r}, expected "
        f"'InvalidParameterValueException'"
    )
    assert message == f"Unrecognized filter name: {bad_filter_name}", (
        f"the unrecognized-filter rejection reported message {message!r}, expected it to "
        f"name the rejected filter {bad_filter_name!r}"
    )

    # Positive control: the documented filter name on the same identifier still matches.
    survivor = dms.describe_replication_subnet_groups(
        Filters=[{"Name": "replication-subnet-group-id", "Values": [sng]}]
    )["ReplicationSubnetGroups"]
    assert len(survivor) == 1, (
        f"the documented filter for {sng!r} returned {len(survivor)} group(s) after the "
        f"rejected unrecognized-filter call, expected exactly 1"
    )
    assert survivor[0]["ReplicationSubnetGroupIdentifier"] == sng, (
        f"the surviving group's identifier reads "
        f"{survivor[0]['ReplicationSubnetGroupIdentifier']!r}, expected {sng!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
