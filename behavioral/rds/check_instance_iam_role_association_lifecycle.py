"""instance-iam-role-association-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-iam-role-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]

_TAGS = [{"Key": "sim2real", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddRoleToDBInstance attaches an IAM role visible in DescribeDBInstances; RemoveRoleFromDBInstance detaches it."""
    rds = ctx.client("rds")

    sng = _subnet_group(ctx)
    role_arn = _create_role(ctx, "rds.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::sim2real-behav-placeholder", "arn:aws:s3:::sim2real-behav-placeholder/*"],
        }],
    })

    inst_id = ctx.unique_name("sim2real-inst-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="dbadmin",
        MasterUserPassword=_password(),
        AllocatedStorage=20,
        DBSubnetGroupName=sng,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    _wait_until(
        lambda: _describe_instance_tolerant(rds, inst_id),
        lambda i: i is not None and i["DBInstanceStatus"] == "available",
        timeout_s=1800, interval_s=30, desc="instance available",
    )

    _add_role_with_retry(rds, inst_id, role_arn, "s3Import")

    # AddRoleToDBInstance (unlike AddRoleToDBCluster) transiently perturbs the INSTANCE's overall
    # DBInstanceStatus while the association propagates, even after the per-role AssociatedRoles
    # entry already reports Status=="ACTIVE". Probing the duplicate-add rejection before the
    # instance has settled back to "available" was observed to race AWS into returning
    # InvalidDBInstanceStateFault instead of the real DBInstanceRoleAlreadyExists — wait for BOTH
    # conditions so the duplicate-add call lands once the instance is actually idle again.
    inst = _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available"
        and any(r["RoleArn"] == role_arn and r["Status"] == "ACTIVE" for r in i.get("AssociatedRoles", [])),
        timeout_s=300, interval_s=10, desc="role association ACTIVE",
    )
    associated = [r for r in inst["AssociatedRoles"] if r["RoleArn"] == role_arn][0]
    assert associated["FeatureName"] == "s3Import", (
        f"expected FeatureName 's3Import' on the settled association, got {associated['FeatureName']!r}"
    )

    try:
        rds.add_role_to_db_instance(DBInstanceIdentifier=inst_id, RoleArn=role_arn, FeatureName="s3Import")
        raise AssertionError("duplicate AddRoleToDBInstance unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        # Real AWS rejects a fully-settled duplicate AddRoleToDBInstance(FeatureName="s3Import")
        # with InvalidParameterValue ("... supports only one ARN associated with feature name
        # s3Import"), not the DBInstanceRoleAlreadyExists the botocore exception shape suggests.
        # The exact message keeps this specific to the duplicate-association rejection rather than
        # any other InvalidParameterValue.
        assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}: {message}"
        expected = "The engine PostgreSQL supports only one ARN associated with feature name s3Import."
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected duplicate must not have left a second entry (or any other
    # trace) behind -- read it independently rather than trusting the rejection alone.
    after_dup = rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    dup_matches = [r for r in after_dup.get("AssociatedRoles", []) if r["RoleArn"] == role_arn]
    assert len(dup_matches) == 1, (
        f"expected exactly one association for {role_arn} after the rejected duplicate add, "
        f"got {len(dup_matches)}: {after_dup.get('AssociatedRoles')!r}"
    )

    rds.remove_role_from_db_instance(DBInstanceIdentifier=inst_id, RoleArn=role_arn, FeatureName="s3Import")

    _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0],
        lambda i: not any(r["RoleArn"] == role_arn for r in i.get("AssociatedRoles", [])),
        timeout_s=180, interval_s=10, desc="role association removed",
    )

    # Restore: the identical call rejected above must now
    # succeed, proving the earlier rejection was specific to the settled duplicate state and
    # not a general inability to associate this role/feature.
    _add_role_with_retry(rds, inst_id, role_arn, "s3Import")
    restored = _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available"
        and any(r["RoleArn"] == role_arn and r["Status"] == "ACTIVE" for r in i.get("AssociatedRoles", [])),
        timeout_s=300, interval_s=10, desc="role re-association ACTIVE after restore",
    )
    restored_assoc = [r for r in restored["AssociatedRoles"] if r["RoleArn"] == role_arn][0]
    assert restored_assoc["FeatureName"] == "s3Import", (
        f"expected FeatureName 's3Import' on the restored association, got {restored_assoc['FeatureName']!r}"
    )


def _password() -> str:
    return "Sim2RealBehav1!"


def _wait_until(probe, predicate, timeout_s, interval_s=20, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last}")
        time.sleep(interval_s)


def _add_role_with_retry(rds, inst_id, role_arn, feature_name, timeout_s=120, interval_s=10):
    # A role created moments ago may not yet be visible to RDS's own IAM lookup; retry the
    # add itself (bounded) rather than guessing a fixed propagation delay.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.add_role_to_db_instance(DBInstanceIdentifier=inst_id, RoleArn=role_arn, FeatureName=feature_name)
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_gone(probe, not_found_codes, timeout_s, interval_s=20, desc="deletion"):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            probe()
        except ClientError as e:
            if e.response["Error"]["Code"] in not_found_codes:
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}")
        time.sleep(interval_s)


def _describe_instance_tolerant(rds, inst_id):
    # DescribeDBInstances can transiently raise DBInstanceNotFound for a brief window right
    # after CreateDBInstance returns, before the new instance's metadata has propagated to the
    # read path. Treat that as "not ready yet" rather than a real failure.
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBInstanceNotFound":
            return None
        raise


def _subnet_group(ctx, name_prefix="sim2real-sng-"):

    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to build a DB subnet group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span enough AZs for a DB subnet group")
    name = ctx.unique_name(name_prefix)
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids[:3],
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _create_role(ctx, service_principal, policy_document, role_name_prefix="sim2real-rdsrole-"):
    iam = ctx.client("iam")
    name = ctx.unique_name(role_name_prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS)["Role"]
    # Cleanups run last-registered-first: the inline policy goes before the role it belongs to.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    pname = f"{name}-policy"
    iam.put_role_policy(RoleName=name, PolicyName=pname, PolicyDocument=json.dumps(policy_document))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=pname))
    return role["Arn"]


def _delete_instance(rds, inst_id):
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id),
        {"DBInstanceNotFound"}, timeout_s=1200, interval_s=20, desc=f"instance {inst_id} deleted",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
