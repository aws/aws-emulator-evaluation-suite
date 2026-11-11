"""concurrency-integration-conflict-operation."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrency-integration-conflict-operation"
GROUP = "concurrency"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing ModifyIntegration against DeleteIntegration: the delete always succeeds and takes
    hold; the modify either wins with its description visible, or is IntegrationConflictStateFault.
    """
    redshift = ctx.client("redshift")
    serverless = ctx.client("redshift-serverless")
    dynamodb = ctx.client("dynamodb")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    ns_name = ctx.unique_name("sim2real-cxns-")
    ns_arn = serverless.create_namespace(
        namespaceName=ns_name, tags=[{"key": "sim2real-behavioral", "value": CHECK}]
    )["namespace"]["namespaceArn"]
    ctx.on_cleanup(lambda: serverless.delete_namespace(namespaceName=ns_name))
    _wait_for_namespace_available(serverless, ns_name)

    # A bare namespace with no workgroup is not resolvable as a zero-ETL integration
    # target and yields IntegrationTargetNotFoundFault -- give it a minimal workgroup,
    # with case-sensitive identifiers enabled (also required for CreateIntegration).
    wg_name = ctx.unique_name("sim2real-cxwg-")
    serverless.create_workgroup(workgroupName=wg_name, namespaceName=ns_name, baseCapacity=8, subnetIds=ctx.network().subnet_ids)
    ctx.on_cleanup(lambda: _best_effort_delete_workgroup(serverless, wg_name))
    _wait_for_workgroup_available(serverless, wg_name)
    serverless.update_workgroup(
        workgroupName=wg_name,
        configParameters=[{"parameterKey": "enable_case_sensitive_identifier", "parameterValue": "true"}],
    )
    _wait_for_workgroup_available(serverless, wg_name)

    table_name = ctx.unique_name("sim2real-cxddb-")
    dynamodb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: dynamodb.delete_table(TableName=table_name))
    _wait_for_table_active(dynamodb, table_name)
    source_arn = dynamodb.describe_table(TableName=table_name)["Table"]["TableArn"]

    _enable_pitr_with_retry(dynamodb, table_name)
    _wait_for_pitr_enabled(dynamodb, table_name)

    # CreateIntegration refuses a DynamoDB source / namespace target that has not
    # authorized the Redshift service (and this caller) via resource policy --
    # without these, it fails deterministically with InvalidParameterValue before
    # the integration is ever created, which would make the race below vacuous.
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
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:redshift:{region}:{account_id}:integration:*"
                    },
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
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:redshift:{region}:{account_id}:integration:*"
                    },
                },
            },
        ],
    }
    dynamodb.put_resource_policy(ResourceArn=source_arn, Policy=json.dumps(ddb_policy))

    rs_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "redshift:AuthorizeInboundIntegration",
                "Resource": ns_arn,
                "Condition": {"StringEquals": {"aws:SourceArn": source_arn}},
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": ns_arn,
            },
        ],
    }
    redshift.put_resource_policy(ResourceArn=ns_arn, Policy=json.dumps(rs_policy))
    ctx.on_cleanup(lambda: _best_effort_delete_resource_policy(redshift, ns_arn))

    integration_name = ctx.unique_name("sim2real-cxint-")
    integration_arn = _create_integration_with_retry(
        redshift,
        SourceArn=source_arn,
        TargetArn=ns_arn,
        IntegrationName=integration_name,
        TagList=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )["IntegrationArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(redshift, integration_arn))
    _wait_for_integration_active(redshift, integration_arn)

    with ThreadPoolExecutor(max_workers=2) as pool:
        modify_future = pool.submit(
            redshift.modify_integration,
            IntegrationArn=integration_arn,
            Description="sim2real-concurrent-modify",
        )
        delete_future = pool.submit(redshift.delete_integration, IntegrationArn=integration_arn)
        modify_result, modify_error = _resolve(modify_future)
        delete_result, delete_error = _resolve(delete_future)

    # Either call may win the race (both can succeed), but the delete is never blocked.
    assert delete_error is None, delete_error
    assert delete_result is not None, "DeleteIntegration must succeed even when raced against a concurrent modify"

    if modify_error is not None:
        # Modify lost: the delete moved the integration out of a modifiable state.
        # IntegrationConflictOperationFault is for racing a still-running create instead.
        assert modify_error.response["Error"]["Code"] == "IntegrationConflictStateFault", modify_error
        expected = "The zero-ETL integration is not in a state that can be modified."
        message = modify_error.response["Error"].get("Message")
        assert message == expected, f"expected {expected!r}, got {message!r}"
    else:
        # Modify won: its description must not be silently dropped by the delete.
        integrations = redshift.describe_integrations(IntegrationArn=integration_arn).get("Integrations", [])
        if integrations:
            assert integrations[0]["Description"] == "sim2real-concurrent-modify", (
                f"modify won the race but its description did not stick: {integrations[0]['Description']!r}"
            )

    final_status = _poll_delete_effect(ctx, redshift, integration_arn, timeout_s=120.0)
    assert final_status in ("deleting", "not_found"), final_status


def _wait_for_table_active(dynamodb, table_name: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = dynamodb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _enable_pitr_with_retry(dynamodb, table_name: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    """A table's continuous backups are still being provisioned for a short window
    right after it becomes ACTIVE; UpdateContinuousBackups rejects with
    ContinuousBackupsUnavailableException until that finishes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            dynamodb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ContinuousBackupsUnavailableException" or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _wait_for_pitr_enabled(dynamodb, table_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = dynamodb.describe_continuous_backups(TableName=table_name)[
            "ContinuousBackupsDescription"
        ]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
        if last_status == "ENABLED":
            return
        time.sleep(3)
    raise AssertionError(f"PITR on {table_name} never reached ENABLED (last={last_status!r})")


def _wait_for_namespace_available(serverless, ns_name: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = serverless.get_namespace(namespaceName=ns_name)["namespace"]["status"]
        if last_status == "AVAILABLE":
            return
        time.sleep(5)
    raise AssertionError(f"namespace {ns_name} never became AVAILABLE (last={last_status!r})")


def _wait_for_workgroup_available(serverless, wg_name: str, timeout_s: float = 600.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = serverless.get_workgroup(workgroupName=wg_name)["workgroup"]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                time.sleep(5)
                continue
            raise
        if last_status == "AVAILABLE":
            return
        time.sleep(2)
    raise AssertionError(f"workgroup {wg_name} never became AVAILABLE (last={last_status!r})")


def _best_effort_delete_workgroup(serverless, wg_name: str, timeout_s: float = 900.0) -> None:
    """Delete the workgroup, waiting out an operation still running on it, and wait until
    it is gone: DeleteNamespace refuses with ConflictException while the namespace still
    has a workgroup."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            serverless.delete_workgroup(workgroupName=wg_name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # A workgroup still serving the integration's teardown refuses with ConflictException.
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(15)
    while time.monotonic() < deadline:
        try:
            serverless.get_workgroup(workgroupName=wg_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(10)
    raise AssertionError(f"workgroup {wg_name} still present {timeout_s}s after DeleteWorkgroup")


def _create_integration_with_retry(redshift, timeout_s: float = 240.0, interval_s: float = 10.0, **kwargs):
    """Retry, bounded, on the transient faults new resource policies cause while propagating:
    not-found, and the InvalidParameterValue the zero-ETL docs attribute to policy propagation."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return redshift.create_integration(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            transient = code in ("IntegrationTargetNotFoundFault", "IntegrationSourceNotFoundFault") or (
                code == "InvalidParameterValue" and "required permissions" in message
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_for_integration_active(redshift, integration_arn: str, timeout_s: float = 600.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        integrations = redshift.describe_integrations(IntegrationArn=integration_arn)["Integrations"]
        last_status = integrations[0]["Status"] if integrations else None
        if last_status == "active":
            return
        if last_status == "failed":
            raise AssertionError(f"integration {integration_arn} entered 'failed' while awaiting active")
        time.sleep(2)
    raise AssertionError(
        f"integration {integration_arn} never became active within {timeout_s}s (last={last_status!r})"
    )


def _best_effort_delete_resource_policy(redshift, resource_arn: str) -> None:
    try:
        redshift.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundFault":
            raise


def _resolve(future):
    try:
        return future.result(), None
    except ClientError as exc:
        return None, exc


def _poll_delete_effect(ctx, redshift, integration_arn: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = redshift.describe_integrations(IntegrationArn=integration_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "IntegrationNotFoundFault":
                return "not_found"
            raise
        integrations = resp.get("Integrations", [])
        if not integrations:
            return "not_found"
        if integrations[0]["Status"] == "deleting":
            return "deleting"
        time.sleep(5)
    return "timeout"


def _best_effort_delete(redshift, integration_arn: str) -> None:
    try:
        redshift.delete_integration(IntegrationArn=integration_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "IntegrationNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
