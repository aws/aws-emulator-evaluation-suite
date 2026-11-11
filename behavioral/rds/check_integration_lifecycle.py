"""integration-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "integration-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]

_MASTER_PW = "Sim2RealBehav1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Aurora-to-Redshift Serverless zero-ETL integration becomes active, shows a modified
    Description on describe, and once deleted rejects ModifyIntegration with IntegrationNotFoundFault."""
    rds = ctx.client("rds")
    subnet_ids = _default_subnet_ids(ctx)
    subnet_group = _create_subnet_group(ctx, subnet_ids)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    pg_name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name,
        DBParameterGroupFamily="aurora-mysql8.0",
        Description="sim2real behavioral check - zero-ETL prerequisites",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=pg_name))
    rds.modify_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name,
        Parameters=[
            {"ParameterName": "binlog_format", "ParameterValue": "ROW", "ApplyMethod": "pending-reboot"},
            {"ParameterName": "binlog_row_image", "ParameterValue": "full", "ApplyMethod": "pending-reboot"},
            # Real AWS also requires binlog_row_metadata=FULL for zero-ETL; without it
            # CreateIntegration rejects with InvalidParameterCombination naming this parameter.
            {"ParameterName": "binlog_row_metadata", "ParameterValue": "FULL", "ApplyMethod": "pending-reboot"},
            {"ParameterName": "binlog_backup", "ParameterValue": "0", "ApplyMethod": "pending-reboot"},
            # Real AWS rejects aurora_enhanced_binlog=1 unless binlog_replication_globaldb is
            # explicitly disabled first ("To enable the aurora_enhanced_binlog parameter, the
            # binlog_replication_globaldb parameter must be disabled") -- this cluster isn't part
            # of an Aurora global database, but the parameter still defaults to enabled and must
            # be turned off before enhanced binlog (required for zero-ETL) can be turned on.
            {"ParameterName": "binlog_replication_globaldb", "ParameterValue": "0", "ApplyMethod": "pending-reboot"},
            {"ParameterName": "aurora_enhanced_binlog", "ParameterValue": "1", "ApplyMethod": "pending-reboot"},
        ],
    )

    cluster_id = ctx.unique_name("sim2real-behav-cl-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="simadmin",
        MasterUserPassword=_MASTER_PW,
        DBSubnetGroupName=subnet_group,
        DBClusterParameterGroupName=pg_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))

    instance_id = ctx.unique_name("sim2real-behav-in-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        DBInstanceClass="db.t4g.medium",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, instance_id))
    _wait_instance_status(ctx, instance_id, {"available"}, timeout_s=1500.0)
    cluster = _wait_cluster_status(ctx, cluster_id, {"available"})
    cluster_arn = cluster["DBClusterArn"]

    redshift_serverless = ctx.client("redshift-serverless")
    redshift = ctx.client("redshift")
    namespace_name = ctx.unique_name("sim2real-behav-ns-")
    redshift_serverless.create_namespace(
        namespaceName=namespace_name, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_and_wait_gone(
        lambda: redshift_serverless.delete_namespace(namespaceName=namespace_name),
        lambda: redshift_serverless.get_namespace(namespaceName=namespace_name),
        {"ResourceNotFoundException"},
        f"namespace {namespace_name}",
    ))
    namespace_arn = _wait_namespace_available(ctx, namespace_name)["namespaceArn"]

    workgroup_name = ctx.unique_name("sim2real-behav-wg-")
    redshift_serverless.create_workgroup(
        workgroupName=workgroup_name,
        namespaceName=namespace_name,
        baseCapacity=8,
        publiclyAccessible=False,
        subnetIds=subnet_ids,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_workgroup_and_wait(redshift_serverless, workgroup_name))
    _wait_workgroup_status(ctx, workgroup_name, {"AVAILABLE"}, timeout_s=1200.0)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "redshift:AuthorizeInboundIntegration",
                "Resource": namespace_arn,
                "Condition": {"StringEquals": {"aws:SourceArn": cluster_arn}},
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": namespace_arn,
            },
        ],
    }
    redshift.put_resource_policy(ResourceArn=namespace_arn, Policy=json.dumps(policy))

    integration_name = ctx.unique_name("sim2real-behav-itg-")
    try:
        resp = rds.create_integration(
            IntegrationName=integration_name,
            SourceArn=cluster_arn,
            TargetArn=namespace_arn,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    except ClientError as e:
        raise AssertionError(f"zero-ETL integration prerequisites not satisfied in this environment: {e}")
    integration_arn = resp["IntegrationArn"]
    ctx.on_cleanup(lambda: _safe_delete_integration(rds, integration_arn, timeout_s=900.0))

    integration = _wait_integration_status(ctx, integration_arn, {"active", "failed"}, timeout_s=2700.0)
    if integration["Status"] == "failed":
        raise AssertionError(f"integration failed to become active: {integration.get('Errors')}")

    rds.modify_integration(IntegrationIdentifier=integration_arn, Description="sim2real updated description")
    integration = _wait_integration_status(ctx, integration_arn, {"active"}, timeout_s=600.0)
    assert integration["Description"] == "sim2real updated description", (
        f"expected modify_integration's Description to be visible on an independent describe, "
        f"got {integration['Description']!r}"
    )

    _delete_integration_when_target_idle(rds, integration_arn, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    _wait_integration_gone(ctx, integration_arn)

    try:
        rds.modify_integration(IntegrationIdentifier=integration_arn, Description="post-delete-should-fail")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "IntegrationNotFoundFault", f"expected IntegrationNotFoundFault on deleted integration, got {code}"
        message = e.response["Error"].get("Message")
        expected = (
            f"Integration with identifier {integration_arn} could not be found. The integration "
            f"might have been deleted, or you provided an incorrect identifier. Check the "
            f"integration identifier and try again."
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError("modify_integration on a deleted integration unexpectedly succeeded")


def _delete_integration_when_target_idle(rds, integration_arn: str, timeout_s: float, ctx=None) -> None:
    """DeleteIntegration, retried only while it is refused because another operation runs on the
    Redshift target (IntegrationConflictOperationFault), until timeout_s."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.delete_integration(IntegrationIdentifier=integration_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "IntegrationConflictOperationFault":
                raise
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"DeleteIntegration {integration_arn} accepted: the run budget ended first; not graded") from e
                raise
            time.sleep(2)


def _safe_delete_integration(rds, integration_arn: str, timeout_s: float) -> None:
    """Teardown: delete the integration once its target is idle and wait until it is gone, so the
    cluster and namespace teardowns that follow are not blocked by it."""
    try:
        _delete_integration_when_target_idle(rds, integration_arn, timeout_s)
    except ClientError as e:
        if e.response["Error"]["Code"] != "IntegrationNotFoundFault":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if not rds.describe_integrations(IntegrationIdentifier=integration_arn)["Integrations"]:
                return
        except ClientError as e:
            if e.response["Error"]["Code"] == "IntegrationNotFoundFault":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"integration {integration_arn} was not deleted within {timeout_s}s")


def _delete_and_wait_gone(delete, probe, not_found: set[str], what: str, timeout_s: float = 1800.0) -> None:
    """Delete, then poll until the describe raises one of the not-found codes.

    A delete refused because another operation still runs on the resource is retried.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in not_found:
                return
            busy = code in ("ConflictException", "InvalidDBClusterStateFault", "InvalidDBInstanceState")
            if not busy or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    while time.monotonic() < deadline:
        try:
            probe()
        except ClientError as e:
            if e.response["Error"]["Code"] in not_found:
                return
            raise
        time.sleep(2)
    raise AssertionError(f"{what} was not deleted within {timeout_s}s")


def _delete_instance_and_wait(rds, instance_id: str) -> None:
    _delete_and_wait_gone(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True),
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id),
        {"DBInstanceNotFound", "DBInstanceNotFoundFault"},
        f"DB instance {instance_id}",
    )


def _delete_cluster_and_wait(rds, cluster_id: str) -> None:
    _delete_and_wait_gone(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True),
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id),
        {"DBClusterNotFoundFault"},
        f"DB cluster {cluster_id}",
    )


def _delete_workgroup_and_wait(rss, workgroup_name: str) -> None:
    _delete_and_wait_gone(
        lambda: rss.delete_workgroup(workgroupName=workgroup_name),
        lambda: rss.get_workgroup(workgroupName=workgroup_name),
        {"ResourceNotFoundException"},
        f"workgroup {workgroup_name}",
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_subnet_ids(ctx, count: int = 3) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ids = sorted({s["SubnetId"] for s in subnets})[:count]
    assert len(ids) >= 2, "need at least 2 subnets to create a DB subnet group"
    return ids


def _create_subnet_group(ctx, subnet_ids: list[str]) -> str:
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _wait_cluster_status(ctx, cluster_id: str, statuses: set[str], timeout_s: float = 1200.0, interval_s: float = 2.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    return _poll_until(probe, lambda c: c["Status"] in statuses, timeout_s=_budget_s(ctx, timeout_s), interval_s=interval_s, ctx=ctx)


def _wait_instance_status(ctx, instance_id: str, statuses: set[str], timeout_s: float = 1500.0, interval_s: float = 2.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(probe, lambda i: i["DBInstanceStatus"] in statuses, timeout_s=_budget_s(ctx, timeout_s), interval_s=interval_s, ctx=ctx)


def _wait_namespace_available(ctx, namespace_name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> dict[str, Any]:
    rss = ctx.client("redshift-serverless")

    def probe():
        return rss.get_namespace(namespaceName=namespace_name)["namespace"]

    return _poll_until(probe, lambda n: n["status"] == "AVAILABLE", timeout_s=_budget_s(ctx, timeout_s), interval_s=interval_s, ctx=ctx)


def _wait_workgroup_status(ctx, workgroup_name: str, statuses: set[str], timeout_s: float = 1200.0, interval_s: float = 2.0) -> dict[str, Any]:
    rss = ctx.client("redshift-serverless")

    def probe():
        return rss.get_workgroup(workgroupName=workgroup_name)["workgroup"]

    return _poll_until(probe, lambda w: w["status"] in statuses, timeout_s=_budget_s(ctx, timeout_s), interval_s=interval_s, ctx=ctx)


def _wait_integration_status(ctx, integration_arn: str, statuses: set[str], timeout_s: float = 1800.0, interval_s: float = 2.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_integrations(IntegrationIdentifier=integration_arn)["Integrations"][0]

    return _poll_until(probe, lambda i: i["Status"] in statuses, timeout_s=_budget_s(ctx, timeout_s), interval_s=interval_s, ctx=ctx)


def _wait_integration_gone(ctx, integration_arn: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> None:
    rds = ctx.client("rds")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = rds.describe_integrations(IntegrationIdentifier=integration_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "IntegrationNotFoundFault":
                return
            raise
        if not resp["Integrations"]:
            return
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"integration {integration_arn} gone: the run budget ended first; not graded")
    raise AssertionError(f"integration {integration_arn} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
