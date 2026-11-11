"""server-side-resource-policy-enforcement."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-resource-policy-enforcement"
GROUP = "server-side"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Without a namespace resource policy, CreateIntegration is rejected synchronously with
    InvalidParameterValue; with the namespace (and DynamoDB table) policies attached, the same
    request is not rejected for authorization, so the policy is enforced, not inert metadata.
    """
    redshift = ctx.client("redshift")
    serverless = ctx.client("redshift-serverless")
    dynamodb = ctx.client("dynamodb")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Two distinct namespace targets, not one reused for both legs -- CreateIntegration
    # against a namespace that already hosted an immediately-preceding create attempt
    # (even a synchronously-rejected one) can transiently misreport
    # IntegrationTargetNotFoundFault, which is a target-churn artifact unrelated to the
    # authorization behavior under test.
    ns_denied_name = ctx.unique_name("sim2real-rpns-deny-")
    ns_denied_arn = _create_namespace(ctx, serverless, ns_denied_name)

    # The unauthorized (denied) leg is rejected before CreateIntegration ever resolves the
    # target's compute, so a bare namespace suffices there. The authorized (allowed) leg
    # must clear that later validation stage too: a namespace with no workgroup is not a
    # resolvable integration target and yields IntegrationTargetNotFoundFault regardless of
    # authorization, so only this leg needs a workgroup bound to its namespace.
    ns_allowed_name = ctx.unique_name("sim2real-rpns-allow-")
    ns_allowed_arn = _create_namespace(ctx, serverless, ns_allowed_name)
    _create_workgroup(ctx, serverless, ns_allowed_name)

    _table_denied_name, table_denied_arn = _create_pitr_table(ctx, dynamodb)
    table_allowed_name, table_allowed_arn = _create_pitr_table(ctx, dynamodb)

    # --- negative: no resource policy authorizes table_denied_arn -> CreateIntegration
    # itself validates authorization synchronously and rejects up front (it never reaches
    # an async 'creating' state for this class of rejection) ---
    denied_name = ctx.unique_name("sim2real-int-denied-")
    denied_resp, denied_error = _create_integration_retryable(
        redshift,
        table_denied_arn,
        ns_denied_arn,
        denied_name,
        tag_list=[{"Key": "sim2real-behavioral", "Value": CHECK}],
        timeout_s=_budget_s(ctx, 60.0),
        ctx=ctx,
    )
    if denied_resp is not None:
        ctx.on_cleanup(
            lambda arn=denied_resp["IntegrationArn"]: _best_effort_delete_integration(redshift, arn)
        )
    denied_code, denied_message = denied_error or (None, None)
    assert denied_code == "InvalidParameterValue", (
        f"expected a synchronous InvalidParameterValue rejection for the unauthorized "
        f"source table, got success={denied_resp!r} code={denied_code!r}"
    )
    expected_denied = (
        "You don't have access to zero-ETL integrations because the Amazon Redshift data "
        "warehouse doesn't exist or you don't have the required permissions. Check the resource "
        "policy of the data warehouse and make sure your user or role is specified as an "
        "authorized principal."
    )
    assert denied_message == expected_denied, (
        f"expected message {expected_denied!r}, got {denied_message!r}"
    )

    denied_matches = redshift.describe_integrations(
        Filters=[{"Name": "source-arn", "Values": [table_denied_arn]}]
    )["Integrations"]
    assert denied_matches == [], (
        f"the rejected source table must not have created any integration, found {denied_matches!r}"
    )

    # --- positive control: attach an authorizing resource policy first ---
    # Redshift's namespace-side policy alone is not sufficient -- DynamoDB also
    # gates the export via its own table-side resource policy.
    dynamodb.put_resource_policy(
        ResourceArn=table_allowed_arn,
        Policy=json.dumps(_ddb_source_policy(account_id, ctx.region, table_allowed_name)),
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S2rAuthorizeInbound",
                "Effect": "Allow",
                "Principal": {"Service": "redshift.amazonaws.com"},
                "Action": "redshift:AuthorizeInboundIntegration",
                "Resource": ns_allowed_arn,
                "Condition": {"StringEquals": {"aws:SourceArn": table_allowed_arn}},
            },
            {
                "Sid": "S2rCreateInbound",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": ns_allowed_arn,
            },
        ],
    }
    redshift.put_resource_policy(ResourceArn=ns_allowed_arn, Policy=json.dumps(policy))
    ctx.on_cleanup(lambda: _best_effort_delete_policy(redshift, ns_allowed_arn))

    allowed_name = ctx.unique_name("sim2real-int-allowed-")
    allowed_resp, allowed_create_err = _create_integration_retryable(
        redshift,
        table_allowed_arn,
        ns_allowed_arn,
        allowed_name,
        tag_list=[{"Key": "sim2real-behavioral", "Value": CHECK}],
        retry_auth=True,
        timeout_s=_budget_s(ctx, 60.0),
        ctx=ctx,
    )
    assert allowed_resp is not None, (
        f"authorized CreateIntegration unexpectedly failed with {allowed_create_err!r}"
    )
    allowed_arn = allowed_resp["IntegrationArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_integration(redshift, allowed_arn))

    allowed_status, _allowed_errors = _poll_integration_terminal(
        ctx, redshift, allowed_arn, timeout_s=_budget_s(ctx, 300.0)
    )
    if allowed_status in (None, "creating", "modifying") and _budget_spent(ctx):
        raise TimeoutError(f"integration {allowed_arn} settled: the run budget ended first; not graded")
    # With the resource policy authorizing this exact source, the integration must
    # not be rejected for lack of authorization (it may still be 'creating' /
    # 'syncing' at the poll deadline -- only 'failed' proves the enforcement gate
    # is broken for an authorized principal).
    assert allowed_status != "failed", allowed_status


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_namespace(ctx, serverless, ns_name: str) -> str:
    ns = serverless.create_namespace(
        namespaceName=ns_name,
        tags=[{"key": "sim2real-behavioral", "value": CHECK}],
    )["namespace"]
    ns_arn = ns["namespaceArn"]
    ctx.on_cleanup(lambda: _delete_namespace(serverless, ns_name))
    _wait_for_namespace_available(serverless, ns_name, timeout_s=_budget_s(ctx, 300.0), ctx=ctx)
    return ns_arn


def _create_workgroup(ctx, serverless, namespace_name: str) -> None:
    workgroup_name = ctx.unique_name("sim2real-rpwg-")
    serverless.create_workgroup(
        workgroupName=workgroup_name,
        namespaceName=namespace_name,
        baseCapacity=8,
        tags=[{"key": "sim2real-behavioral", "value": CHECK}],
        subnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(lambda: _delete_workgroup(serverless, workgroup_name))
    _wait_for_workgroup_available(serverless, workgroup_name, timeout_s=_budget_s(ctx, 900.0), ctx=ctx)
    # Zero-ETL integrations require case-sensitive identifiers on the target warehouse.
    serverless.update_workgroup(
        workgroupName=workgroup_name,
        configParameters=[{"parameterKey": "enable_case_sensitive_identifier", "parameterValue": "true"}],
    )
    _wait_for_workgroup_available(serverless, workgroup_name, timeout_s=_budget_s(ctx, 900.0), ctx=ctx)


def _wait_for_workgroup_available(serverless, workgroup_name: str, timeout_s: float = 900.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            wg = serverless.get_workgroup(workgroupName=workgroup_name)["workgroup"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                time.sleep(1)
                continue
            raise
        status = wg["status"]
        if status == "AVAILABLE":
            return wg
        if status in ("FAILED", "DELETING"):
            raise AssertionError(f"workgroup {workgroup_name} entered unexpected status {status}")
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"workgroup {workgroup_name} AVAILABLE: the run budget ended first; not graded")
    raise AssertionError(f"workgroup {workgroup_name} did not become AVAILABLE within {timeout_s}s")


def _retry_conflict(fn, timeout_s: float = 600.0) -> bool:
    """Run a teardown delete, retrying while another operation (an integration or workgroup
    still being deleted) holds the resource. False when the resource is already gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return True
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return False
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _delete_namespace(serverless, ns_name: str) -> None:
    _retry_conflict(lambda: serverless.delete_namespace(namespaceName=ns_name))


def _delete_workgroup(serverless, workgroup_name: str) -> None:
    if not _retry_conflict(lambda: serverless.delete_workgroup(workgroupName=workgroup_name)):
        return
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline:
        try:
            serverless.get_workgroup(workgroupName=workgroup_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)


def _create_pitr_table(ctx, dynamodb) -> tuple[str, str]:
    table_name = ctx.unique_name("sim2real-rpddb-")
    dynamodb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: dynamodb.delete_table(TableName=table_name))
    _wait_for_table_active(dynamodb, table_name, timeout_s=_budget_s(ctx, 120.0), ctx=ctx)
    _update_continuous_backups_with_retry(dynamodb, table_name, timeout_s=_budget_s(ctx, 120.0), ctx=ctx)
    table_arn = dynamodb.describe_table(TableName=table_name)["Table"]["TableArn"]
    return table_name, table_arn


def _update_continuous_backups_with_retry(
    dynamodb, table_name: str, *, timeout_s: float = 120.0, interval_s: float = 2.0, ctx=None
) -> None:
    # Immediately after a table becomes ACTIVE, its continuous-backups infrastructure
    # can still be settling, which makes UpdateContinuousBackups transiently reject with
    # ContinuousBackupsUnavailableException. Retry within a bound instead of treating
    # this as a hard failure.
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            dynamodb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ContinuousBackupsUnavailableException":
                raise
            last_err = err
            time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"PITR on {table_name} accepted: the run budget ended first; not graded") from last_err
    raise AssertionError(f"UpdateContinuousBackups still unavailable after {timeout_s}s: {last_err}")


def _ddb_source_policy(account_id: str, region: str, table_name: str) -> dict:
    integration_arn_pattern = f"arn:aws:redshift:{region}:{account_id}:integration:*"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S2rAllowRedshiftDescribeAndExport",
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
                "Sid": "S2rAllowRedshiftDescribeExport",
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


def _create_integration_retryable(
    redshift, source_arn: str, target_arn: str, name: str, *, tag_list=None, retry_auth=False,
    timeout_s: float = 60.0, ctx=None,
):
    """CreateIntegration against a namespace created moments earlier can transiently
    answer IntegrationTargetNotFoundFault even though GetNamespace already reports
    AVAILABLE -- a propagation lag on the CreateIntegration validation path itself, not a
    property of either call site's authorization. Absorb it here for both. When
    retry_auth is set (the authorized call site only), also absorb the resource-policy
    propagation lag on the specific permission error -- never on the unauthorized call
    site, where that same error is the assertion under test.

    Returns (response, (error_code, error_message)): exactly one is not None.
    """
    kwargs = {"SourceArn": source_arn, "TargetArn": target_arn, "IntegrationName": name}
    if tag_list is not None:
        kwargs["TagList"] = tag_list
    last_err: ClientError | None = None
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return redshift.create_integration(**kwargs), None
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = str(err.response["Error"].get("Message", ""))
            transient_target = code == "IntegrationTargetNotFoundFault"
            transient_auth = retry_auth and code == "InvalidParameterValue" and (
                "doesn't exist or you don't have" in msg or "resource policy" in msg.lower()
            )
            if (transient_target or transient_auth) and time.monotonic() < deadline:
                last_err = err
                time.sleep(2)
                continue
            if transient_target or transient_auth:
                break
            return None, (code, msg)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"CreateIntegration {name} accepted: the run budget ended first; not graded") from last_err
    raise AssertionError(f"CreateIntegration still failing after retries: {last_err}")


def _wait_for_namespace_available(serverless, ns_name: str, timeout_s: float = 300.0, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = serverless.get_namespace(namespaceName=ns_name)["namespace"]["status"]
        if status == "AVAILABLE":
            return
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"namespace {ns_name} AVAILABLE: the run budget ended first; not graded")
    raise AssertionError(f"namespace {ns_name} never became AVAILABLE (last status: {status})")


def _wait_for_table_active(dynamodb, table_name: str, timeout_s: float = 120.0, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = dynamodb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"table {table_name} ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"table {table_name} never became ACTIVE")


def _poll_integration_terminal(ctx, redshift, integration_arn: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    status = None
    errors: list = []
    while time.monotonic() < deadline:
        resp = redshift.describe_integrations(IntegrationArn=integration_arn)
        integrations = resp.get("Integrations", [])
        if not integrations:
            time.sleep(1)
            continue
        status = integrations[0]["Status"]
        errors = integrations[0].get("Errors", [])
        if status not in ("creating", "modifying"):
            return status, errors
        time.sleep(1)
    return status, errors


def _best_effort_delete_integration(redshift, integration_arn: str) -> None:
    try:
        redshift.delete_integration(IntegrationArn=integration_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "IntegrationNotFoundFault":
            raise


def _best_effort_delete_policy(redshift, resource_arn: str) -> None:
    try:
        redshift.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
