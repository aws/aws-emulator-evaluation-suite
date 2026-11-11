"""rds-associate-role-missing-trust-policy-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-associate-role-missing-trust-policy-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]

# InvalidDBClusterStateFault: the cluster is mid-operation. InvalidParameterValue: IAM
# trust-policy changes are not immediately consistent, so RDS can keep re-validating
# against the pre-update policy for a short window right after an update.
_RETRYABLE_CODES = ("InvalidDBClusterStateFault", "InvalidParameterValue")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddRoleToDBCluster with a role not trusted by rds.amazonaws.com is rejected with
    InvalidParameterValue and records nothing, a trusted role reaches ACTIVE, and the rejected role
    reaches ACTIVE once its trust policy is fixed."""
    _, subnet_ids = _default_vpc_subnets(ctx)
    subnet_group = _create_subnet_group(ctx, subnet_ids)
    cluster_id = _create_minimal_cluster(ctx, subnet_group)
    rds = ctx.client("rds")
    iam = ctx.client("iam")

    # Break exactly one thing: the role's trust policy names ec2.amazonaws.com, not
    # rds.amazonaws.com, so RDS can never assume it.
    untrusted_role_name, untrusted_role_arn = _create_role(ctx, "ec2.amazonaws.com")
    error = _expect_rejected(
        lambda: rds.add_role_to_db_cluster(
            DBClusterIdentifier=cluster_id, RoleArn=untrusted_role_arn, FeatureName="s3Import"
        )
    )
    assert error.get("Code") == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    expected_message = (
        "IAM role ARN value is invalid or does not include the required permissions for: "
        "AWS_ROLE_INTEGRATION"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect absent: the rejected call never recorded an association at all.
    associated_arns = _associated_role_arns(rds, cluster_id)
    assert untrusted_role_arn not in associated_arns, (
        f"rejected role association was recorded anyway: {associated_arns}"
    )

    # Positive control in the same file: a fresh role with the correct trust relationship
    # is accepted and settles ACTIVE on the very same cluster.
    _, trusted_role_arn = _create_role(ctx, "rds.amazonaws.com")
    good_status = _add_role_settled(ctx, rds, cluster_id, trusted_role_arn, "s3Export")
    assert good_status == "ACTIVE", f"expected trusted role association to reach ACTIVE, got {good_status!r}"

    # Restore: fix the trust policy on the SAME role that was just rejected, then retry
    # the IDENTICAL call. It must now succeed -- the rejection tracked the role's trust
    # policy, not something pinned to the role's identity forever.
    _update_role_trust(iam, untrusted_role_name, "rds.amazonaws.com")
    restored_status = _add_role_settled(ctx, rds, cluster_id, untrusted_role_arn, "s3Import")
    assert restored_status == "ACTIVE", (
        f"expected the identical call to succeed once trust was restored, got {restored_status!r}"
    )


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to build a DB subnet group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span >=2 AZs required for a DB subnet group")
    return vpc_id, list(by_az.values())[:3]


def _create_subnet_group(ctx, subnet_ids):
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _create_minimal_cluster(ctx, subnet_group):
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-cluster-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="sim2real",
        MasterUserPassword="Sim2RealTest1234!",
        DBSubnetGroupName=subnet_group,
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))
    waiter = rds.get_waiter("db_cluster_available")
    waiter.wait(DBClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600})
    return cluster_id


def _create_role(ctx, trust_service):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, resp["Role"]["Arn"]


def _update_role_trust(iam, role_name, trust_service):
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(trust))


def _expect_rejected(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _associated_role_arns(rds, cluster_id):
    desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    return [r["RoleArn"] for r in desc.get("AssociatedRoles", [])]


def _add_role_settled(ctx, rds, cluster_id, role_arn, feature_name, attempts=12, delay_s=5):
    last_exc = None
    for _ in range(attempts):
        try:
            rds.add_role_to_db_cluster(
                DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name
            )
            ctx.on_cleanup(
                lambda: rds.remove_role_from_db_cluster(
                    DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name
                )
            )
            break
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] not in _RETRYABLE_CODES:
                raise
            time.sleep(delay_s)
    else:
        raise last_exc
    return _poll_associated_role_status(rds, cluster_id, role_arn, feature_name, timeout_s=300)


def _poll_associated_role_status(rds, cluster_id, role_arn, feature_name, timeout_s=300, interval_s=10):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        for role in _associated_roles(rds, cluster_id):
            if role["RoleArn"] == role_arn and role.get("FeatureName") == feature_name:
                last = role["Status"]
                if last in ("ACTIVE", "INVALID"):
                    return last
        time.sleep(interval_s)
    raise AssertionError(
        f"role {role_arn} association on {cluster_id} never settled within {timeout_s}s "
        f"(last observed: {last!r})"
    )


def _associated_roles(rds, cluster_id):
    return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0].get(
        "AssociatedRoles", []
    )


def _delete_cluster_and_wait(rds, cluster_id, timeout_s=900, interval_s=15):
    """Delete the cluster and block until it is gone, so the subnet group teardown that
    runs next does not find the cluster still holding it."""
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} was not deleted within {timeout_s}s")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
