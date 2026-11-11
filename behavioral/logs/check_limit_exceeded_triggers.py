"""limit-exceeded-triggers."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "limit-exceeded-triggers"
GROUP = 'resource-policy'
SERVICES = ['logs']


def _make_events(messages, start_ts_ms=None, step_ms=1000):
    base = start_ts_ms if start_ts_ms is not None else int(time.time() * 1000)
    return [{"timestamp": base + i * step_ms, "message": m} for i, m in enumerate(messages)]


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_log_group(svc, name):
    desc = svc.describe_log_groups(logGroupNamePrefix=name)
    for g in desc.get("logGroups", []):
        if g["logGroupName"] == name:
            return g
    raise AssertionError(f"log group {name!r} not found via DescribeLogGroups")


def _wait_query_terminal(svc, query_id, *, timeout_s=90):
    return _poll_until(
        lambda: svc.get_query_results(queryId=query_id),
        lambda r: r.get("status") in ("Complete", "Failed", "Cancelled", "Timeout"),
        timeout_s=timeout_s,
        interval_s=2.0,
        description="query reaches a terminal status",
    )


def _export_bucket_policy(bucket_name, region, account, log_group_arn_with_star):
    principal = {"Service": f"logs.{region}.amazonaws.com"}
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowGetBucketAcl",
                    "Action": "s3:GetBucketAcl",
                    "Effect": "Allow",
                    "Resource": f"arn:aws:s3:::{bucket_name}",
                    "Principal": principal,
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": [account]},
                        "ArnLike": {"aws:SourceArn": [log_group_arn_with_star]},
                    },
                },
                {
                    "Sid": "AllowPutObject",
                    "Action": "s3:PutObject",
                    "Effect": "Allow",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Principal": principal,
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control",
                            "aws:SourceAccount": [account],
                        },
                        "ArnLike": {"aws:SourceArn": [log_group_arn_with_star]},
                    },
                },
            ],
        }
    )


def _delete_bucket(s3, bucket):
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data", "resource:account-singleton:logs-account-policy", "resource:account-singleton:logs-export-task", "resource:account-singleton:logs-integration", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """PutResourcePolicy past the 10-per-account/region cap fails with LimitExceededException;
    the other quota-bearing operations, whose quotas are too high to hit, run in a valid context.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html
    """
    svc = ctx.client("logs")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-lg-limits-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group, logStreamName=stream, logEvents=_make_events(["limit-probe-event"])
    )
    _poll_until(
        lambda: svc.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True),
        lambda r: len(r.get("events", [])) >= 1,
        timeout_s=30,
        interval_s=2.0,
        description="the probe event lands",
    )
    group_arn = _describe_log_group(svc, group)["logGroupArn"]

    # -- LimitExceededException at the real 10-resource-policy-per-account cap.
    created_policies: list[str] = []
    try:
        existing = svc.describe_resource_policies(policyScope="ACCOUNT").get("resourcePolicies", [])
        slots_free = max(0, 10 - len(existing))
        policy_doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowRoute53",
                        "Effect": "Allow",
                        "Principal": {"Service": "route53.amazonaws.com"},
                        "Action": "logs:PutLogEvents",
                        "Resource": "*",
                    }
                ],
            }
        )
        for i in range(slots_free):
            pname = ctx.unique_name(f"sim2real-behav-respol-{i}-")
            svc.put_resource_policy(policyName=pname, policyDocument=policy_doc)
            created_policies.append(pname)

        overflow_name = ctx.unique_name("sim2real-behav-respol-overflow-")
        code, code_msg = _error_code(
            lambda: svc.put_resource_policy(policyName=overflow_name, policyDocument=policy_doc)
        )
        assert code == "LimitExceededException", (
            f"expected LimitExceededException at the 10-resource-policy cap, got {code!r} "
            f"(had {len(existing)} pre-existing + {len(created_policies)} newly created)"
        )
        assert code_msg == "Resource limit exceeded.", (
            f"expected message 'Resource limit exceeded.', got {code_msg!r}"
        )
    finally:
        for pname in created_policies:
            try:
                svc.delete_resource_policy(policyName=pname)
            except Exception:  # noqa: BLE001 — best-effort teardown
                pass

    # -- Exercise the remaining quota-bearing operations end-to-end.
    detector_arn = svc.create_log_anomaly_detector(logGroupArnList=[group_arn])["anomalyDetectorArn"]
    try:
        got_detector = svc.get_log_anomaly_detector(anomalyDetectorArn=detector_arn)
        assert got_detector.get("logGroupArnList") == [group_arn], (
            f"unexpected detector detail: {got_detector!r}"
        )
    finally:
        svc.delete_log_anomaly_detector(anomalyDetectorArn=detector_arn)

    filter_name = ctx.unique_name("sim2real-behav-mf-")
    svc.put_metric_filter(
        logGroupName=group,
        filterName=filter_name,
        filterPattern="ERROR",
        metricTransformations=[
            {"metricName": "LimitProbeErrors", "metricNamespace": "sim2real/behavioral", "metricValue": "1"}
        ],
    )
    svc.delete_metric_filter(logGroupName=group, filterName=filter_name)

    sub_code, sub_code_msg = _error_code(
        lambda: svc.put_subscription_filter(
            logGroupName=group,
            filterName=ctx.unique_name("sim2real-behav-subf-"),
            filterPattern="ERROR",
            destinationArn="not-a-valid-destination-arn",
        )
    )
    assert sub_code is not None, "expected PutSubscriptionFilter with a malformed destinationArn to fail"

    svc.put_transformer(logGroupIdentifier=group, transformerConfig=[{"parseJSON": {}}])

    table_name = ctx.unique_name("sim2real_behav_lut_").replace("-", "_")
    table_arn = svc.create_lookup_table(lookupTableName=table_name, tableBody="k,v\n1,a\n")["lookupTableArn"]
    svc.delete_lookup_table(lookupTableArn=table_arn)

    # The rest of openSearchResourceConfig is well-formed so botocore's client-side
    # validation does not reject the request before it reaches the service.
    integ_code, integ_code_msg = _error_code(
        lambda: svc.put_integration(
            integrationName=ctx.unique_name("sim2real-behav-integ-"),
            integrationType="NOT_A_REAL_INTEGRATION_TYPE",
            resourceConfig={
                "openSearchResourceConfig": {
                    "dataSourceRoleArn": f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-bogus-')}",
                    "dashboardViewerPrincipals": [
                        f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-viewer-')}"
                    ],
                    "retentionDays": 7,
                }
            },
        )
    )
    assert integ_code == "InvalidParameterException", (
        f"expected PutIntegration with integrationType='NOT_A_REAL_INTEGRATION_TYPE' to fail "
        f"with InvalidParameterException, got {integ_code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'integrationType' failed to satisfy constraint: "
        "Member must satisfy enum value set: [OPENSEARCH]"
    )
    assert integ_code_msg == expected, f"expected message {expected!r}, got {integ_code_msg!r}"
    del_integ_code, del_integ_code_msg = _error_code(
        lambda: svc.delete_integration(integrationName=ctx.unique_name("sim2real-behav-integ-missing-"), force=True)
    )
    assert del_integ_code is not None, "expected DeleteIntegration against a nonexistent integration to fail"

    assoc_s3t_code, assoc_s3t_code_msg = _error_code(
        lambda: svc.associate_source_to_s3_table_integration(
            integrationArn=(
                f"arn:aws:logs:{ctx.region}:{account}:integration:{ctx.unique_name('sim2real-behav-s3t-')}"
            ),
            dataSource={"name": group, "type": "LOG_GROUP"},
        )
    )
    assert assoc_s3t_code is not None, (
        "expected AssociateSourceToS3TableIntegration against a nonexistent integration to fail"
    )

    policy_name = ctx.unique_name("sim2real-behav-acctpol-")
    # The data protection account policy is account-wide: restore the prior set afterwards.
    prior_policies = svc.describe_account_policies(policyType="DATA_PROTECTION_POLICY")["accountPolicies"]
    ctx.on_cleanup(lambda: _restore_account_policies(svc, prior_policies))
    svc.put_account_policy(
        policyName=policy_name,
        policyType="DATA_PROTECTION_POLICY",
        policyDocument=json.dumps(
            {
                "Name": policy_name,
                "Version": "2021-06-01",
                "Statement": [
                    {
                        "Sid": "audit",
                        "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                        "Operation": {"Audit": {"FindingsDestination": {}}},
                    },
                    {
                        "Sid": "redact",
                        "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                        "Operation": {"Deidentify": {"MaskConfig": {}}},
                    },
                ],
            }
        ),
    )
    svc.delete_account_policy(policyName=policy_name, policyType="DATA_PROTECTION_POLICY")

    svc.put_data_protection_policy(
        logGroupIdentifier=group,
        policyDocument=json.dumps(
            {
                "Name": group,
                "Version": "2021-06-01",
                "Statement": [
                    {
                        "Sid": "audit",
                        "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                        "Operation": {"Audit": {"FindingsDestination": {}}},
                    },
                    {
                        "Sid": "redact",
                        "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                        "Operation": {"Deidentify": {"MaskConfig": {}}},
                    },
                ],
            }
        ),
    )
    svc.delete_data_protection_policy(logGroupIdentifier=group)

    svc.put_index_policy(logGroupIdentifier=group, policyDocument=json.dumps({"Fields": ["requestId"]}))
    idx_policies = svc.describe_index_policies(logGroupIdentifiers=[group])
    assert idx_policies.get("indexPolicies"), f"expected an index policy to be listed: {idx_policies!r}"
    svc.delete_index_policy(logGroupIdentifier=group)

    del_dest_code, del_dest_code_msg = _error_code(
        lambda: svc.delete_destination(destinationName=ctx.unique_name("sim2real-behav-dest-missing-"))
    )
    assert del_dest_code is not None, "expected DeleteDestination against a nonexistent destination to fail"

    # CreateExportTask / CancelExportTask: a real, immediately-cancelled export.
    export_bucket = ctx.unique_name("sim2real-behav-export-limitscov-")[:63].rstrip("-")
    create_kwargs = {"Bucket": export_bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda _b=export_bucket: _delete_bucket(s3, _b))
    group_arn_star = _describe_log_group(svc, group)["arn"]
    s3.put_bucket_policy(
        Bucket=export_bucket,
        Policy=_export_bucket_policy(export_bucket, ctx.region, account, group_arn_star),
    )
    now_ms = int(time.time() * 1000)
    export_task_id = svc.create_export_task(
        logGroupName=group, **{"from": 0}, to=now_ms, destination=export_bucket
    )["taskId"]
    try:
        svc.cancel_export_task(taskId=export_task_id)
        cancel_code = None
    except ClientError as exc:
        cancel_code = exc.response.get("Error", {}).get("Code")
    final_export_status = _poll_until(
        lambda: svc.describe_export_tasks(taskId=export_task_id)["exportTasks"][0]["status"]["code"],
        lambda s: s in ("CANCELLED", "COMPLETED", "FAILED"),
        timeout_s=60,
        interval_s=2.0,
        description="export task reaches a terminal status",
    )
    if cancel_code is None:
        assert final_export_status == "CANCELLED", (
            f"CancelExportTask succeeded but the task ended as {final_export_status!r}"
        )
    else:
        assert final_export_status in ("COMPLETED", "FAILED"), (
            f"CancelExportTask was rejected as too-late but the task is {final_export_status!r}"
        )

    qdef_id = svc.put_query_definition(
        name=ctx.unique_name("sim2real-behav-qdef-"), queryString="fields @timestamp | limit 5"
    )["queryDefinitionId"]
    svc.delete_query_definition(queryDefinitionId=qdef_id)

    now = int(time.time())
    query_id = svc.start_query(
        logGroupName=group,
        startTime=now - 3600,
        endTime=now + 3600,
        queryString="fields @timestamp, @message, @ptr | limit 1",
    )["queryId"]
    result = _wait_query_terminal(svc, query_id)
    assert result["status"] == "Complete", f"expected the coverage query to complete, got {result['status']!r}"

    fields_resp = svc.get_log_group_fields(logGroupName=group)
    assert "logGroupFields" in fields_resp, (
        f"expected GetLogGroupFields to return a logGroupFields key, got {fields_resp!r}"
    )

    field_indexes = svc.describe_field_indexes(logGroupIdentifiers=[group])
    assert "fieldIndexes" in field_indexes, (
        f"expected DescribeFieldIndexes to return a fieldIndexes key, got {field_indexes!r}"
    )

    rows = result.get("results", [])
    if rows:
        ptr = next((f["value"] for f in rows[0] if f["field"] == "@ptr"), None)
        if ptr:
            record = svc.get_log_record(logRecordPointer=ptr)
            assert "logRecord" in record, (
                f"expected GetLogRecord({ptr!r}) to return a logRecord key, got {record!r}"
            )


def _restore_account_policies(svc, prior):
    """Make the account's data protection policies exactly the ones read before the check."""
    kind = "DATA_PROTECTION_POLICY"
    kept = {p["policyName"] for p in prior}
    for p in svc.describe_account_policies(policyType=kind)["accountPolicies"]:
        if p["policyName"] not in kept:
            svc.delete_account_policy(policyName=p["policyName"], policyType=kind)
    for p in prior:
        kwargs = {"policyName": p["policyName"], "policyDocument": p["policyDocument"], "policyType": kind}
        if p.get("scope"):
            kwargs["scope"] = p["scope"]
        svc.put_account_policy(**kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
