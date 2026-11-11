"""integration-create-delete-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "integration-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["redshift"]

MSG_BAD_TARGET = (
    "You don't have access to zero-ETL integrations because the Amazon Redshift data warehouse "
    "doesn't exist or you don't have the required permissions. Check the resource policy of the "
    "data warehouse and make sure your user or role is specified as an authorized principal."
)
MSG_INBOUND_BOGUS = "The requested namespace doesn't exist."
MSG_REDELETE = "The requested integration doesn't exist."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A zero-ETL integration from DynamoDB becomes visible via DescribeIntegrations/Inbound and goes
    'creating' -> 'active', then DeleteIntegration removes it; a nonexistent target namespace is
    rejected up front and never becomes observable."""
    redshift = ctx.client("redshift")
    dynamodb = ctx.client("dynamodb")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    # ---- source: a DynamoDB table with PITR + a resource policy authorizing Redshift ----
    table_name = ctx.unique_name("sim2real-behav-ddb-")
    dynamodb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: dynamodb.delete_table(TableName=table_name))
    _wait_table_active(ctx, table_name, timeout_s=_budget_s(ctx, 120))
    table_arn = dynamodb.describe_table(TableName=table_name)["Table"]["TableArn"]
    _enable_pitr_with_retry(dynamodb, table_name, timeout_s=_budget_s(ctx, 120), ctx=ctx)
    dynamodb.put_resource_policy(
        ResourceArn=table_arn,
        Policy=json.dumps(_ddb_source_policy(account_id, region, table_name)),
    )

    # ---- target: an RA3 cluster with case-sensitive identifiers enabled ----
    pg_name = ctx.unique_name("sim2real-behav-pg-")
    redshift.create_cluster_parameter_group(
        ParameterGroupName=pg_name,
        ParameterGroupFamily="redshift-1.0",
        Description="sim2real zero-ETL case sensitivity",
    )
    ctx.on_cleanup(lambda: _delete_parameter_group_quiet(redshift, pg_name))
    redshift.modify_cluster_parameter_group(
        ParameterGroupName=pg_name,
        Parameters=[{"ParameterName": "enable_case_sensitive_identifier", "ParameterValue": "true"}],
    )

    cluster_id = ctx.unique_name("sim2real-behav-tgt-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword="S2rBehav3ral!9",
        ClusterParameterGroupName=pg_name,
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(redshift, cluster_id))
    cluster = _wait_cluster_status(ctx, cluster_id, "available", timeout_s=_budget_s(ctx, 1200))
    namespace_arn = cluster["ClusterNamespaceArn"]

    redshift.put_resource_policy(
        ResourceArn=namespace_arn,
        Policy=json.dumps(_namespace_policy(account_id, namespace_arn, table_arn)),
    )
    ctx.on_cleanup(lambda: _delete_resource_policy_quiet(redshift, namespace_arn))

    # ---- negative control: target namespace that doesn't exist ----
    # A wholly nonexistent target ARN (never created, unlike a real-but-unreachable
    # namespace) is rejected synchronously by CreateIntegration itself with the bare
    # ClientError code "InvalidParameterValue". The
    # IntegrationTargetNotFoundFault code is reserved for a target ARN that resolves to
    # a real resource but fails a deeper, asynchronous validation surfaced later via
    # DescribeIntegrations' Errors field, not for an ARN whose namespace never existed.
    bogus_namespace = (
        f"arn:aws:redshift:{region}:{account_id}:namespace:00000000-0000-0000-0000-000000000000"
    )
    code, message = _refusal(
        lambda: redshift.create_integration(
            SourceArn=table_arn,
            TargetArn=bogus_namespace,
            IntegrationName=ctx.unique_name("sim2real-behav-badtgt-"),
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a nonexistent target namespace, got {code!r}"
    )
    assert message == MSG_BAD_TARGET, f"expected {MSG_BAD_TARGET!r}, got {message!r}"
    # DescribeInboundIntegrations validates the target namespace's own existence before
    # it would ever list anything against it, so a namespace that was never created
    # 404s the read itself (InvalidNamespaceFault) rather than answering with an empty
    # list.
    inbound_bogus_code, inbound_bogus_message = _refusal(
        lambda: redshift.describe_inbound_integrations(TargetArn=bogus_namespace)
    )
    assert inbound_bogus_code == "InvalidNamespaceFault", (
        f"expected the still-nonexistent target namespace to 404 on describe, "
        f"got {inbound_bogus_code!r}"
    )
    assert inbound_bogus_message == MSG_INBOUND_BOGUS, (
        f"expected {MSG_INBOUND_BOGUS!r}, got {inbound_bogus_message!r}"
    )

    # ---- positive: the real integration lifecycle ----
    integration_name = ctx.unique_name("sim2real-behav-itg-")
    create_resp = redshift.create_integration(
        SourceArn=table_arn,
        TargetArn=namespace_arn,
        IntegrationName=integration_name,
    )
    integration_arn = create_resp["IntegrationArn"]
    assert create_resp["Status"] == "creating", (
        f"expected a freshly created integration to start in 'creating', got {create_resp['Status']!r}"
    )
    ctx.on_cleanup(lambda: _delete_integration_quiet(redshift, integration_arn))

    status = _poll_until(
        lambda: redshift.describe_integrations(IntegrationArn=integration_arn)["Integrations"][0][
            "Status"
        ],
        lambda s: s in ("active", "failed", "needs_attention"),
        timeout_s=_budget_s(ctx, 1800),
        interval_s=2,
        ctx=ctx,
    )
    assert status == "active", f"expected the integration to settle into 'active', got {status!r}"

    listed = redshift.describe_integrations(IntegrationArn=integration_arn)["Integrations"]
    assert len(listed) == 1, f"expected exactly one integration for this ARN, got {len(listed)}"
    assert listed[0]["IntegrationName"] == integration_name, (
        f"expected IntegrationName {integration_name!r}, got {listed[0]['IntegrationName']!r}"
    )

    inbound_active = redshift.describe_inbound_integrations(TargetArn=namespace_arn)[
        "InboundIntegrations"
    ]
    assert any(i["IntegrationArn"] == integration_arn for i in inbound_active), (
        f"expected {integration_arn} among the target namespace's inbound integrations, "
        f"got {[i['IntegrationArn'] for i in inbound_active]!r}"
    )

    redshift.delete_integration(IntegrationArn=integration_arn)
    _poll_until(
        lambda: _integration_exists(redshift, integration_arn),
        lambda exists: not exists,
        timeout_s=_budget_s(ctx, 600),
        interval_s=2,
        ctx=ctx,
    )

    # The delete must also make a mutation on the now-dead ARN fail with the
    # specific not-found code, not merely stop appearing in reads.
    redelete_code, redelete_message = _refusal(
        lambda: redshift.delete_integration(IntegrationArn=integration_arn)
    )
    assert redelete_code == "IntegrationNotFoundFault", (
        f"expected deleting an already-deleted integration to 404 as IntegrationNotFoundFault, "
        f"got {redelete_code!r}"
    )
    assert redelete_message == MSG_REDELETE, f"expected {MSG_REDELETE!r}, got {redelete_message!r}"

    # The parameter group can only be removed once the cluster is gone; that wait is longer
    # than the teardown budget, so it happens here.
    _delete_resource_policy_quiet(redshift, namespace_arn)
    _delete_cluster_and_wait(redshift, cluster_id, timeout_s=_budget_s(ctx, 1200.0), ctx=ctx)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, ctx=None):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition never met within {timeout_s}s (last value: {value!r})")


def _wait_cluster_status(ctx, cluster_id: str, target_status: str, timeout_s: float = 1200.0):
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        last = cluster["ClusterStatus"]
        if last == target_status:
            return cluster
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} never reached '{target_status}' (last status: {last})"
    )


def _delete_cluster_and_wait(redshift, cluster_id: str, timeout_s: float = 1200.0, ctx=None) -> None:
    """Delete the cluster and wait until it is gone, so its parameter group can follow."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState":
                raise
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"DeleteCluster {cluster_id} accepted: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)
    while time.monotonic() < deadline:
        try:
            redshift.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ClusterNotFound":
                return
            raise
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} gone: the run budget ended first; not graded")
    raise AssertionError(f"cluster {cluster_id} was not gone within {timeout_s}s")


def _delete_parameter_group_quiet(redshift, pg_name: str) -> None:
    try:
        redshift.delete_cluster_parameter_group(ParameterGroupName=pg_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterParameterGroupNotFound":
            raise


def _enable_pitr_with_retry(dynamodb, table_name: str, *, timeout_s: float = 120.0, ctx=None) -> None:
    """DynamoDB's backup subsystem is not immediately ready when a table reports ACTIVE:
    real AWS rejects UpdateContinuousBackups with ContinuousBackupsUnavailableException
    ("Backups are being enabled for the table... retry later") for a bounded window right
    after CreateTable, so this must be a retry, not a single call."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            dynamodb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ContinuousBackupsUnavailableException":
                raise
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"PITR on {table_name} accepted: the run budget ended first; not graded") from exc
                raise AssertionError(
                    f"table {table_name} never accepted UpdateContinuousBackups within {timeout_s}s"
                ) from exc
            time.sleep(2)


def _wait_table_active(ctx, table_name: str, timeout_s: float = 120.0):
    dynamodb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dynamodb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if last == "ACTIVE":
            return
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"table {table_name} ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"table {table_name} never became ACTIVE (last status: {last})")


def _integration_exists(redshift, integration_arn: str) -> bool:
    try:
        redshift.describe_integrations(IntegrationArn=integration_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "IntegrationNotFoundFault":
            return False
        raise
    return True


def _delete_integration_quiet(redshift, integration_arn: str) -> None:
    try:
        redshift.delete_integration(IntegrationArn=integration_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("IntegrationNotFoundFault", "IntegrationConflictStateFault"):
            raise


def _delete_resource_policy_quiet(redshift, resource_arn: str) -> None:
    try:
        redshift.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundFault":
            raise


def _ddb_source_policy(account_id: str, region: str, table_name: str) -> dict[str, Any]:
    integration_arn_pattern = f"arn:aws:redshift:{region}:{account_id}:integration:*"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRedshiftDescribeAndExport",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": ["dynamodb:ExportTableToPointInTime", "dynamodb:DescribeTable"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": integration_arn_pattern},
                },
            },
            {
                "Sid": "AllowRedshiftDescribeExport",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "dynamodb:DescribeExport",
                "Resource": f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}/export/*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": integration_arn_pattern},
                },
            },
        ],
    }


def _namespace_policy(account_id: str, namespace_arn: str, source_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "redshift:AuthorizeInboundIntegration",
                "Resource": namespace_arn,
                "Condition": {"StringEquals": {"aws:SourceArn": source_arn}},
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": namespace_arn,
            },
        ],
    }


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
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
