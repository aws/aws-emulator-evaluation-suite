"""e2e-integration-zero-etl-lifecycle-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-integration-zero-etl-lifecycle-flow"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DynamoDB->Redshift zero-ETL integration transitions its inbound integration
    to active on the target namespace, and deleting the integration makes the
    inbound integration disappear from the target as the true consequence."""
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = ctx.region

    dynamodb = ctx.client("dynamodb")
    redshift = ctx.client("redshift")
    rss = ctx.client("redshift-serverless")

    # --- source: a PITR-enabled DynamoDB table with a resource policy allowing
    # the Redshift service to export it -----------------------------------------
    table_name = ctx.unique_name("sim2real-zetl-tbl-")
    dynamodb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: dynamodb.delete_table(TableName=table_name))
    dynamodb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    table_arn = f"arn:aws:dynamodb:{region}:{account}:table/{table_name}"

    _update_backups_when_ready(
        ctx,
        dynamodb,
        TableName=table_name,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )
    _poll_until(
        lambda: dynamodb.describe_continuous_backups(TableName=table_name)[
            "ContinuousBackupsDescription"
        ]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"],
        lambda status: status == "ENABLED",
        timeout_s=60,
        interval_s=3,
    )

    ddb_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRedshiftDescribeAndExport",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": ["dynamodb:ExportTableToPointInTime", "dynamodb:DescribeTable"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:redshift:{region}:{account}:integration:*"
                    },
                },
            },
            {
                "Sid": "AllowRedshiftDescribeExport",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "dynamodb:DescribeExport",
                "Resource": f"arn:aws:dynamodb:{region}:{account}:table/{table_name}/export/*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:redshift:{region}:{account}:integration:*"
                    },
                },
            },
        ],
    }
    dynamodb.put_resource_policy(ResourceArn=table_arn, Policy=json.dumps(ddb_policy))

    # --- target: a Redshift Serverless namespace with a resource policy that
    # authorizes this DynamoDB table as an integration source --------------------
    ns_name = ctx.unique_name("sim2real-zetl-ns-")
    ns = rss.create_namespace(
        namespaceName=ns_name,
        tags=[{"key": "sim2real-behavioral", "value": "true"}],
    )["namespace"]
    ctx.on_cleanup(lambda: _retry_while_held(lambda: rss.delete_namespace(namespaceName=ns_name), "ConflictException", timeout_s=600.0))
    _poll_until(
        lambda: rss.get_namespace(namespaceName=ns_name)["namespace"]["status"],
        lambda status: status == "AVAILABLE",
        timeout_s=300,
        interval_s=5,
    )
    namespace_arn = ns["namespaceArn"]

    # A namespace alone is not a complete "data warehouse": CreateIntegration answers
    # IntegrationTargetNotFoundFault for a namespace with no workgroup, so an attached workgroup
    # (the compute half of a serverless data warehouse) is required for the namespace to become a
    # valid integration target.
    workgroup_name = ctx.unique_name("sim2real-zetl-wg-")
    rss.create_workgroup(
        namespaceName=ns_name,
        workgroupName=workgroup_name,
        tags=[{"key": "sim2real-behavioral", "value": "true"}],
        subnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(lambda: rss.delete_workgroup(workgroupName=workgroup_name))
    _poll_until(
        lambda: rss.get_workgroup(workgroupName=workgroup_name)["workgroup"]["status"],
        lambda status: status == "AVAILABLE",
        timeout_s=600,
        interval_s=10,
    )

    rs_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "redshift:AuthorizeInboundIntegration",
                "Resource": namespace_arn,
                "Condition": {"StringEquals": {"aws:SourceArn": table_arn}},
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": namespace_arn,
            },
        ],
    }
    redshift.put_resource_policy(ResourceArn=namespace_arn, Policy=json.dumps(rs_policy))

    # --- create the zero-ETL integration and observe it go active --------------
    # Just-applied resource policies and a just-AVAILABLE namespace can take a while to become
    # visible to CreateIntegration, which answers InvalidParameterValue ("check the resource and
    # key policy") and then IntegrationTargetNotFoundFault for a namespace that GetNamespace
    # already reports AVAILABLE. Both are the same propagation window, so both are retried by
    # name; anything else is a real failure and is not.
    integration_name = ctx.unique_name("sim2real-zetl-int-")
    integration_arn = _create_integration_with_retry(
        redshift,
        source_arn=table_arn,
        target_arn=namespace_arn,
        name=integration_name,
        tag_list=[{"Key": "sim2real-behavioral", "Value": "true"}],
        timeout_s=600,
        interval_s=20,
    )["IntegrationArn"]
    ctx.on_cleanup(lambda: _delete_integration_if_exists(redshift, integration_arn))

    def _status() -> str:
        resp = redshift.describe_integrations(IntegrationArn=integration_arn)
        return resp["Integrations"][0]["Status"]

    final_status = _poll_until(
        _status,
        lambda status: status in ("active", "failed"),
        timeout_s=1200,
        interval_s=15,
    )
    assert final_status == "active", f"integration reached terminal status {final_status!r}"

    inbound = redshift.describe_inbound_integrations(TargetArn=namespace_arn)[
        "InboundIntegrations"
    ]
    matches = [i for i in inbound if i["IntegrationArn"] == integration_arn]
    assert len(matches) == 1, "inbound integration not visible on the target namespace"
    assert matches[0]["Status"] == "active", (
        f"expected inbound integration status 'active' on target namespace, "
        f"got {matches[0]['Status']!r}"
    )

    # --- delete the integration and observe the inbound integration disappear --
    redshift.delete_integration(IntegrationArn=integration_arn)

    def _still_present() -> bool:
        inbound_now = redshift.describe_inbound_integrations(TargetArn=namespace_arn)[
            "InboundIntegrations"
        ]
        return any(i["IntegrationArn"] == integration_arn for i in inbound_now)

    gone = _poll_until(
        _still_present, lambda present: present is False, timeout_s=300, interval_s=10
    )
    assert gone is False, "inbound integration still visible on target after delete"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _delete_integration_if_exists(redshift, integration_arn: str) -> None:
    try:
        redshift.delete_integration(IntegrationArn=integration_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "IntegrationNotFoundFault":
            raise


def _create_integration_with_retry(
    redshift,
    *,
    source_arn: str,
    target_arn: str,
    name: str,
    tag_list: list,
    timeout_s: float,
    interval_s: float,
):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return redshift.create_integration(
                SourceArn=source_arn,
                TargetArn=target_arn,
                IntegrationName=name,
                TagList=tag_list,
            )
        except ClientError as exc:
            error = exc.response["Error"]
            propagating = error["Code"] == "IntegrationTargetNotFoundFault" or (
                error["Code"] == "InvalidParameterValue"
                and "resource and key policy" in error.get("Message", "")
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=15.0):
    """Run a teardown delete, retrying while AWS refuses it because a dependent resource deleted just
    before it is still going away; after the deadline the last refusal is raised."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


def _update_backups_when_ready(ctx, ddb, **kwargs) -> None:
    """UpdateContinuousBackups, retried while AWS still initialises a new table's backups."""
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else min(120.0, left))
    while True:
        try:
            ddb.update_continuous_backups(**kwargs)
            return
        except ddb.exceptions.ContinuousBackupsUnavailableException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
