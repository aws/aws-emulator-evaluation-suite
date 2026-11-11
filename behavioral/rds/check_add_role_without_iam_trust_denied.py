"""add-role-without-iam-trust-denied."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-role-without-iam-trust-denied"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_MASTER_USER = "sim2realadmin"
_MASTER_PASS = "Sim2RealPwd123"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """AddRoleToDBCluster with a role lacking an rds.amazonaws.com trust relationship is rejected
    synchronously with InvalidParameterValue and records no association, while a properly
    trusted role is accepted and settles ACTIVE."""
    rds = ctx.client("rds")
    iam = ctx.client("iam")

    untrusted_role_arn = _create_role(ctx, iam, trusted_service="ec2.amazonaws.com")
    trusted_role_arn = _create_role(ctx, iam, trusted_service="rds.amazonaws.com")

    cluster_id = ctx.unique_name("sim2real-rolecluster-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))
    _wait_for_cluster_status(rds, cluster_id, "available", timeout_s=600)

    # The association call must be rejected synchronously for the untrusted role.
    code, message = _error_detail(
        lambda: rds.add_role_to_db_cluster(
            DBClusterIdentifier=cluster_id,
            RoleArn=untrusted_role_arn,
            FeatureName="s3Import",
        )
    )
    assert code == "InvalidParameterValue", f"unexpected error code: {code!r}: {message!r}"
    expected = "IAM role ARN value is invalid or does not include the required permissions for: AWS_ROLE_INTEGRATION"
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Effect absent: no association was recorded for the rejected role.
    cluster = _describe_cluster(rds, cluster_id)
    associated_arns = [r["RoleArn"] for r in cluster.get("AssociatedRoles", [])]
    assert untrusted_role_arn not in associated_arns, (
        f"untrusted role was associated despite rejection: {associated_arns}"
    )

    # Positive control (same file): a properly-trusted role is accepted and settles ACTIVE.
    rds.add_role_to_db_cluster(
        DBClusterIdentifier=cluster_id, RoleArn=trusted_role_arn, FeatureName="s3Import"
    )
    trusted_status = _wait_for_role_status_settled(rds, cluster_id, trusted_role_arn, timeout_s=180)
    assert trusted_status == "ACTIVE", f"properly-trusted role failed to activate: {trusted_status!r}"


def _create_role(ctx: Any, iam: Any, *, trusted_service: str) -> str:
    role_name = ctx.unique_name(f"sim2real-rds-role-{trusted_service.split('.')[0]}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trusted_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return role_arn


def _delete_role(iam: Any, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error_detail(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call succeeded; expected a rejection")


def _describe_cluster(rds: Any, cluster_id: str) -> dict[str, Any]:
    return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]


def _wait_for_cluster_status(rds: Any, cluster_id: str, status: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = _describe_cluster(rds, cluster_id)
        if cluster["Status"] == status:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached status={status!r} in {timeout_s}s")


def _role_status(rds: Any, cluster_id: str, role_arn: str) -> str | None:
    cluster = _describe_cluster(rds, cluster_id)
    for role in cluster.get("AssociatedRoles", []):
        if role["RoleArn"] == role_arn:
            return role["Status"]
    return None


def _wait_for_role_status_settled(rds: Any, cluster_id: str, role_arn: str, *, timeout_s: float) -> str:
    """Poll until the association's Status leaves the transient 'PENDING' state."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _role_status(rds, cluster_id, role_arn)
        if last is not None and last != "PENDING":
            return last
        time.sleep(5)
    raise AssertionError(
        f"role {role_arn} association on {cluster_id} never left PENDING "
        f"within {timeout_s}s (last observed: {last!r})"
    )


def _delete_cluster(rds: Any, cluster_id: str) -> None:
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
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
