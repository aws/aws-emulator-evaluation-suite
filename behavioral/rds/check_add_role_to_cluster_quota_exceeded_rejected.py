"""add-role-to-cluster-quota-exceeded-rejected."""
from __future__ import annotations

import json
import secrets
import string
import time

from botocore.exceptions import ClientError

import botocore.exceptions

from behavioral_harness import tags

CHECK = "add-role-to-cluster-quota-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddRoleToDBCluster with a role already associated fails with DBClusterRoleAlreadyExists and
    no duplicate association appears; removing then re-adding the role succeeds."""
    rds = ctx.client("rds")
    iam = ctx.client("iam")

    cluster_id = ctx.unique_name("sim2real-rolequota-")
    password = _rand_password()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1},
        DeletionProtection=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    cluster = _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    # Valid FeatureName values depend on the engine version (SupportedFeatureNames); omitting
    # it falls back to a default association AWS rejects unless the role's permissions fit.
    feature_name = _pick_feature_name(rds, "aurora-mysql", cluster["EngineVersion"])

    role_arn = _create_role(ctx, iam, "role-0")
    _add_role_with_retry(ctx, rds, cluster_id, role_arn, feature_name)
    ctx.on_cleanup(lambda: _remove_role_ignore_missing(rds, cluster_id, role_arn, feature_name))
    _wait_role_count(ctx, cluster_id, 1, timeout_s=120)

    code, message = _error_detail(
        lambda: rds.add_role_to_db_cluster(
            DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name
        )
    )
    assert code == "DBClusterRoleAlreadyExists", f"unexpected error code {code!r}: {message!r}"
    expected = (
        f"Role ARN {role_arn} is already associated with DB Cluster: {cluster_id}. "
        "Verify your role ARN and try again."
    )
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Effect absent: still exactly one association, not duplicated.
    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    associated = cluster.get("AssociatedRoles", [])
    assert len(associated) == 1, f"expected exactly 1 associated role, found {associated!r}"

    # Positive control (same file): removing then re-adding the SAME role succeeds -- the
    # rejection was about the existing association, not a broken cluster or role.
    rds.remove_role_from_db_cluster(
        DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name
    )
    _wait_role_count(ctx, cluster_id, 0, timeout_s=120)
    _add_role_with_retry(ctx, rds, cluster_id, role_arn, feature_name)
    final = _wait_role_count(ctx, cluster_id, 1, timeout_s=120)
    assert final[0]["RoleArn"] == role_arn, f"expected re-added role {role_arn}, got {final!r}"


def _error_detail(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError("call unexpectedly succeeded, expected a rejection")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _create_role(ctx, iam, suffix: str) -> str:
    role_name = ctx.unique_name(f"sim2real-rolequota-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    # Cleanups run LIFO, so the inline policy registered below is removed before the role.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # A bare trust policy is not enough: AddRoleToDBCluster rejects a permission-less role with
    # InvalidParameterValue (AWS_ROLE_INTEGRATION), so attach the S3 access the feature expects.
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                        "Resource": [
                            "arn:aws:s3:::sim2real-behav-placeholder",
                            "arn:aws:s3:::sim2real-behav-placeholder/*",
                        ],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _pick_feature_name(rds, engine, engine_version, preferred="s3Import"):
    versions = rds.describe_db_engine_versions(Engine=engine, EngineVersion=engine_version)["DBEngineVersions"]
    supported = versions[0].get("SupportedFeatureNames", []) if versions else []
    if not supported:
        raise AssertionError(f"engine {engine} {engine_version} advertises no SupportedFeatureNames to test")
    return preferred if preferred in supported else supported[0]


def _remove_role_ignore_missing(rds, cluster_id, role_arn, feature_name) -> None:
    try:
        rds.remove_role_from_db_cluster(
            DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name
        )
    except rds.exceptions.DBClusterRoleNotFoundFault:
        pass
    except rds.exceptions.DBClusterNotFoundFault:
        pass


def _add_role_is_retryable(exc: botocore.exceptions.ClientError) -> bool:
    error = exc.response.get("Error", {})
    if error.get("Code") == "InvalidDBClusterStateFault":
        return True
    # RDS reports a not-yet-propagated IAM role as InvalidParameterValue naming its
    # "AWS_ROLE_INTEGRATION" check rather than as a dedicated retryable fault.
    if error.get("Code") == "InvalidParameterValue" and "AWS_ROLE_INTEGRATION" in error.get("Message", ""):
        return True
    return False


def _add_role_with_retry(ctx, rds, cluster_id, role_arn, feature_name, timeout_s=180, poll_s=2) -> None:
    """AddRoleToDBCluster transiently rejects while the newly created IAM role and its policy
    are still propagating server-side; bounded-retry, not one shot or an unconditional sleep."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.add_role_to_db_cluster(
                DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name
            )
            return
        except botocore.exceptions.ClientError as exc:
            if not _add_role_is_retryable(exc):
                raise
            last_exc = exc
            time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError("AddRoleToDBCluster role propagation: the run budget ended first; not graded")
    raise AssertionError(f"AddRoleToDBCluster never became valid within {timeout_s}s: {last_exc}")


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_role_count(ctx, cluster_id, target_count, timeout_s=120, poll_s=2) -> list:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last: list = []
    while time.monotonic() < deadline:
        cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        last = cluster.get("AssociatedRoles", [])
        if len(last) == target_count:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"cluster {cluster_id} associated-role count {target_count}: the run budget ended first; not graded"
        )
    raise AssertionError(
        f"cluster {cluster_id} associated-role count never reached {target_count}, "
        f"last observed {len(last)}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
