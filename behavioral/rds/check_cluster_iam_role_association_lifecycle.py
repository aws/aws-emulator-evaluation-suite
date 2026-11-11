"""cluster-iam-role-association-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-iam-role-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """AddRoleToDBCluster attaches an IAM role visible in DescribeDBClusters; RemoveRoleFromDBCluster detaches it."""
    rds = ctx.client("rds")
    ctx.client("iam")

    sng = _subnet_group(ctx)
    role_arn = _create_role(ctx, "rds.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::sim2real-behav-placeholder", "arn:aws:s3:::sim2real-behav-placeholder/*"],
        }],
    })

    cluster_id = ctx.unique_name("sim2real-clu-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword=_password(),
        DBSubnetGroupName=sng,
        BackupRetentionPeriod=1,
        StorageEncrypted=True,
        Tags=_check_tags(),
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))

    inst_id = ctx.unique_name("sim2real-cluinst-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        DBInstanceClass="db.t3.medium",
        Engine="aurora-mysql",
        DBClusterIdentifier=cluster_id,
        Tags=_check_tags(),
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    cluster = _wait_until(
        lambda: _describe_cluster_tolerant(rds, cluster_id),
        lambda c: c is not None and c["Status"] == "available",
        timeout_s=1800, interval_s=30, desc="cluster available",
    )

    # The set of valid AddRoleToDBCluster FeatureName values is engine/engine-version specific
    # (see DescribeDBEngineVersions' SupportedFeatureNames); "s3Import" is not one of them for
    # every Aurora MySQL version, so look up a feature this cluster's actual engine version
    # supports rather than assuming one.
    feature_name = _pick_feature_name(rds, "aurora-mysql", cluster["EngineVersion"])

    # Attempting a duplicate role feature name association before adding is a no-op check;
    # exercise the real add first. The role's IAM trust policy can race its own propagation to
    # RDS's control plane on first use, so the add is retried through that window.
    _add_role_with_retry(rds, cluster_id, role_arn, feature_name)

    # A DB cluster's AssociatedRoles entry can take several minutes to move from PENDING to ACTIVE,
    # longer than a DB instance's role association, so the wait is bounded at 900 s.
    cluster = _wait_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: any(r["RoleArn"] == role_arn and r["Status"] == "ACTIVE" for r in c.get("AssociatedRoles", [])),
        timeout_s=900, interval_s=15, desc="role association ACTIVE",
    )
    associated = [r for r in cluster["AssociatedRoles"] if r["RoleArn"] == role_arn][0]
    assert associated["FeatureName"] == feature_name, (
        f"expected AssociatedRoles FeatureName {feature_name!r}, got {associated['FeatureName']!r}"
    )

    # A second attempt to add the exact same role+feature must be rejected, not silently ignored.
    try:
        rds.add_role_to_db_cluster(DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name)
        raise AssertionError("duplicate AddRoleToDBCluster unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code == "DBClusterRoleAlreadyExists", (
            f"expected DBClusterRoleAlreadyExists on duplicate add, got {code!r}"
        )
        expected = (
            f"Role ARN {role_arn} is already associated with DB Cluster: {cluster_id}. "
            "Verify your role ARN and try again."
        )
        assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    rds.remove_role_from_db_cluster(DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name)

    _wait_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: not any(r["RoleArn"] == role_arn for r in c.get("AssociatedRoles", [])),
        timeout_s=300, interval_s=10, desc="role association removed",
    )


def _password() -> str:
    return "Sim2RealBehav1!"


def _check_tags():
    return [{"Key": "sim2real-check", "Value": CHECK}]


def _add_role_with_retry(rds, cluster_id, role_arn, feature_name, timeout_s=120, interval_s=10):
    # A brand-new IAM role's trust policy can lag its propagation to RDS's control plane; retry
    # the first AddRoleToDBCluster through that window.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.add_role_to_db_cluster(DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidParameterValue", "IamRoleNotFound", "IamRoleMissingPermissions"):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _pick_feature_name(rds, engine, engine_version, preferred="s3Import"):
    versions = rds.describe_db_engine_versions(Engine=engine, EngineVersion=engine_version)["DBEngineVersions"]
    supported = versions[0].get("SupportedFeatureNames", []) if versions else []
    if not supported:
        raise AssertionError(f"engine {engine} {engine_version} advertises no SupportedFeatureNames to test")
    return preferred if preferred in supported else supported[0]


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


def _describe_cluster_tolerant(rds, cluster_id):
    # DescribeDBClusters can transiently raise DBClusterNotFoundFault for a brief window right
    # after CreateDBCluster returns, before the new cluster's metadata has propagated to the
    # read path. Treat that as "not ready yet" rather than a real failure.
    try:
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBClusterNotFoundFault":
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
        Tags=_check_tags(),
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
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_check_tags())["Role"]
    # Cleanups run LIFO, so the inline policy registered below is removed before the role.
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


def _delete_cluster(rds, cluster_id):
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id),
        {"DBClusterNotFoundFault"}, timeout_s=1200, interval_s=20, desc=f"cluster {cluster_id} deleted",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
