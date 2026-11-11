"""integration-concurrent-conflict-operation-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "integration-concurrent-conflict-operation-blocked"
GROUP = "concurrency"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second mutating call (DeleteIntegration) against an integration that is still
    'creating' is rejected with IntegrationConflictOperationFault rather than racing the
    in-flight CreateIntegration, and once the integration settles a normal delete succeeds.
    """
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = ctx.region

    ddb = ctx.client("dynamodb")
    rss = ctx.client("redshift-serverless")
    redshift = ctx.client("redshift")
    ec2 = ctx.client("ec2")

    # --- source: a PITR-enabled DynamoDB table with a resource policy authorizing the
    # Redshift service to export it, or CreateIntegration rejects it before ever reaching
    # the create/delete race this check exists to exercise. -----------------------------
    table_name = ctx.unique_name("sim2real-behav-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    try:
        ddb.get_waiter("table_exists").wait(
            TableName=table_name,
            WaiterConfig={"Delay": 1, "MaxAttempts": max(1, int(_budget_s(ctx, 500.0)))},
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(f"table {table_name} ACTIVE: the run budget ended first; not graded") from exc
        raise
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    pitr_deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:  # a just-active table refuses PITR while its backups are still being enabled
        try:
            ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            break
        except ddb.exceptions.ContinuousBackupsUnavailableException:
            if time.monotonic() >= pitr_deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"PITR on {table_name} accepted: the run budget ended first; not graded") from None
                raise
            time.sleep(2)
    _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=table_name)[
            "ContinuousBackupsDescription"
        ]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"],
        lambda status: status == "ENABLED",
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=1,
        ctx=ctx,
    )
    ddb.put_resource_policy(
        ResourceArn=table_arn,
        Policy=json.dumps(
            {
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
                        "Resource": f"{table_arn}/export/*",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": account},
                            "ArnEquals": {
                                "aws:SourceArn": f"arn:aws:redshift:{region}:{account}:integration:*"
                            },
                        },
                    },
                ],
            }
        ),
    )

    # --- target: a namespace + workgroup (a bare namespace is not a resolvable
    # integration target -- CreateIntegration rejects it with IntegrationTargetNotFoundFault)
    # carrying a resource policy that authorizes this table as an inbound integration source.
    ns_name = ctx.unique_name("sim2real-behav-ns-").lower()
    rss.create_namespace(namespaceName=ns_name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_namespace(rss, ns_name))
    ns_arn = _wait_namespace_available(ctx, ns_name)

    vpc_id = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"][0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    az_to_subnet: dict[str, str] = {}
    for sn in subnets:
        az_to_subnet.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    subnet_ids = list(az_to_subnet.values())[:3]
    assert len(subnet_ids) >= 3, "shared network needs subnets in >= 3 AZs to host a serverless workgroup"

    wg_name = ctx.unique_name("sim2real-behav-wg-").lower()
    rss.create_workgroup(
        workgroupName=wg_name,
        namespaceName=ns_name,
        subnetIds=subnet_ids,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_workgroup(rss, wg_name))
    _wait_workgroup_available(rss, wg_name, timeout_s=_budget_s(ctx, 900.0), ctx=ctx)

    redshift.put_resource_policy(
        ResourceArn=ns_arn,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "redshift.amazonaws.com"},
                        "Action": "redshift:AuthorizeInboundIntegration",
                        "Resource": ns_arn,
                        "Condition": {
                            "StringEquals": {"aws:SourceArn": table_arn, "aws:SourceAccount": account}
                        },
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "redshift:CreateInboundIntegration",
                        "Resource": ns_arn,
                        "Condition": {
                            "StringEquals": {"aws:SourceArn": table_arn, "aws:SourceAccount": account}
                        },
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_resource_policy(redshift, ns_arn))

    integration_name = ctx.unique_name("sim2real-behav-integ-")
    resp = _create_integration_with_retry(
        redshift, timeout_s=_budget_s(ctx, 240.0), ctx=ctx, IntegrationName=integration_name, SourceArn=table_arn, TargetArn=ns_arn
    )
    integration_arn = resp["IntegrationArn"]
    ctx.on_cleanup(lambda: _delete_integration_ignore_missing(redshift, integration_arn))

    status_before = resp["Status"]
    assert status_before in ("creating", "active"), status_before

    # Race a delete against the still-in-flight create while status != active/failed.
    if status_before != "active":
        code, message = _error(lambda: redshift.delete_integration(IntegrationArn=integration_arn))
        assert code == "IntegrationConflictOperationFault", code
        assert message == (
            "Unable to perform delete operation on the specified zero-ETL integration because its "
            "target Redshift data warehouse is not active. Wait until the data warehouse is active "
            "and try again."
        ), (
            f"unexpected IntegrationConflictOperationFault message {message!r}"
        )

        # Effect absent: the integration must still exist and not be transitioning to delete.
        still_there = redshift.describe_integrations(IntegrationArn=integration_arn)
        assert still_there["Integrations"], "integration disappeared after rejected delete"
        assert still_there["Integrations"][0]["Status"] != "deleting"

    # Positive control: once the integration reaches a terminal non-busy status, a normal
    # delete must succeed (proves the earlier rejection was state-specific, not a stub that
    # always rejects DeleteIntegration).
    final_status = _poll_until(
        lambda: redshift.describe_integrations(IntegrationArn=integration_arn)["Integrations"][0]["Status"],
        lambda s: s in ("active", "failed", "needs_attention"),
        timeout_s=_budget_s(ctx, 1500.0),
        interval_s=2,
        ctx=ctx,
    )
    if final_status not in ("active",):
        raise AssertionError(
            f"integration settled into '{final_status}' instead of 'active' within the "
            "poll window; cannot exercise the positive-control delete deterministically"
        )
    redshift.delete_integration(IntegrationArn=integration_arn)
    _poll_until(
        lambda: _integration_gone(redshift, integration_arn),
        lambda gone: gone,
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=1,
        ctx=ctx,
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


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _error_code_from_exc(exc) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _delete_integration_ignore_missing(redshift, integration_arn: str) -> None:
    """Delete the integration (retrying while it is busy) and wait until DescribeIntegrations no
    longer finds it, so the workgroup teardown that follows does not collide with it."""
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        try:
            redshift.delete_integration(IntegrationArn=integration_arn)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "IntegrationNotFoundFault":
                return
            if code in ("IntegrationConflictOperationFault", "IntegrationConflictStateFault"):
                time.sleep(2)
                continue
            raise
    while time.monotonic() < deadline:
        try:
            redshift.describe_integrations(IntegrationArn=integration_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "IntegrationNotFoundFault":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"integration {integration_arn} was not deleted within 1200s")


def _integration_gone(redshift, integration_arn: str) -> bool:
    try:
        resp = redshift.describe_integrations(IntegrationArn=integration_arn)
    except Exception as exc:  # noqa: BLE001
        return _error_code_from_exc(exc) == "IntegrationNotFoundFault"
    integrations = resp.get("Integrations", [])
    return not integrations or integrations[0]["Status"] == "deleting"


def _wait_namespace_available(ctx, ns_name: str) -> str:
    rss = ctx.client("redshift-serverless")
    deadline = time.monotonic() + _budget_s(ctx, 300.0)
    while time.monotonic() < deadline:
        ns = rss.get_namespace(namespaceName=ns_name)["namespace"]
        if ns["status"] == "AVAILABLE":
            return ns["namespaceArn"]
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"namespace {ns_name} AVAILABLE: the run budget ended first; not graded")
    raise AssertionError("redshift-serverless namespace never reached AVAILABLE")


def _wait_workgroup_available(rss, wg_name: str, timeout_s: float = 900.0, interval_s: float = 1.0, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = rss.get_workgroup(workgroupName=wg_name)["workgroup"]["status"]
        if last_status == "AVAILABLE":
            return
        if last_status in ("FAILED",):
            raise AssertionError(f"workgroup {wg_name} entered status {last_status!r}")
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"workgroup {wg_name} AVAILABLE: the run budget ended first; not graded")
    raise AssertionError(f"workgroup {wg_name} did not become AVAILABLE within {timeout_s}s (last={last_status})")


def _delete_workgroup(rss, wg_name: str) -> None:
    """Delete the workgroup and wait until it is gone. DeleteWorkgroup answers ConflictException
    while an integration teardown is still running against it, so retry through that."""
    deadline = time.monotonic() + 1500
    while time.monotonic() < deadline:
        try:
            status = rss.get_workgroup(workgroupName=wg_name)["workgroup"]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status != "DELETING":
            try:
                rss.delete_workgroup(workgroupName=wg_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("ConflictException", "ResourceNotFoundException"):
                    raise
        time.sleep(2)
    raise AssertionError(f"workgroup {wg_name} was not deleted within 1500s")


def _delete_namespace(rss, ns_name: str) -> None:
    """Delete the namespace once its workgroup is gone; retry ConflictException and wait for it to vanish."""
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            status = rss.get_namespace(namespaceName=ns_name)["namespace"]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status != "DELETING":
            try:
                rss.delete_namespace(namespaceName=ns_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("ConflictException", "ResourceNotFoundException"):
                    raise
        time.sleep(2)
    raise AssertionError(f"namespace {ns_name} was not deleted within 900s")


def _delete_resource_policy(redshift, resource_arn: str) -> None:
    try:
        redshift.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundFault":
            raise


def _create_integration_with_retry(redshift, timeout_s: float = 240.0, interval_s: float = 2.0, ctx=None, **kwargs):
    """CreateIntegration can transiently report the just-authorized namespace/table as not
    found while cross-service ARN resolution and resource-policy propagation catch up; retry
    on that specific fault only, bounded, rather than treating it as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return redshift.create_integration(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("IntegrationTargetNotFoundFault", "IntegrationSourceNotFoundFault"):
                raise
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError("CreateIntegration resolving its source and target: the run budget ended first; not graded") from exc
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, ctx=None):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if predicate(value):
        return value
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
