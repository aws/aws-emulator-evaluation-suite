"""query-state-change-event-carries-athenaerror-only-when-the-query-failed."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "query-state-change-event-carries-athenaerror-only-when-the-query-failed"
GROUP = "event-propagation"
SERVICES = ["athena", "events", "sqs"]

_SOURCE = "aws.athena"
_DETAIL_TYPE = "Athena Query State Change"


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, then the bucket; Athena writes result files into the output location."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "athena-query-state-change-event"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _output_location(ctx):
    return f"s3://{_make_bucket(ctx, 'sim2real-xsvc-athena-results-')}/results/"


def _start_query(athena, out, query_string, workgroup=None, database=None):
    kwargs = {"QueryString": query_string}
    if out:
        kwargs["ResultConfiguration"] = {"OutputLocation": out}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a terminal state with a bounded deadline; raises on timeout."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _run_sql(athena, out, sql, database=None, workgroup=None):
    qid = _start_query(athena, out, sql, database=database, workgroup=workgroup)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}")
    return qid


def _dml_name(database, table):
    """DML goes through the Trino parser (double-quoted identifiers); DDL through Hive
    (backticks)."""
    return f'"{database}"."{table}"'


def _queue(ctx):
    """A tagged SQS queue with its cleanup registered; returns (url, arn)."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-athena-evt-")
    url = sqs.create_queue(QueueName=name, tags={
        "sim2real": "athena-query-state-change-event", "sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"]
    return url, arn


def _rule_to_queue(ctx, workgroup, queue_url, queue_arn):
    """A default-bus EventBridge rule targeting the queue, narrowed to this check's workgroup so a
    concurrent run's events cannot match."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    rule = ctx.unique_name("sim2real-xsvc-athena-evt-rule-")
    pattern = {
        "source": [_SOURCE],
        "detail-type": [_DETAIL_TYPE],
        "detail": {"workgroupName": [workgroup]},
    }
    rule_arn = events.put_rule(
        Name=rule, EventPattern=json.dumps(pattern), State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": "athena-query-state-change-event"},
              {"Key": "sim2real:managed", "Value": "true"}])["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule))
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridgeDelivery",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    })})
    events.put_targets(Rule=rule, Targets=[{"Id": "queue", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["queue"]))
    return rule


def _collect_event(ctx, queue_url, *, query_execution_id, current_state, timeout_s=180,
                   description="event"):
    """Drain the queue until the event for this execution id in this state arrives; raises on
    timeout. Non-matching messages are deleted as they are read.
    """
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            detail = body["detail"]
            if (detail["queryExecutionId"] == query_execution_id
                    and detail["currentState"] == current_state):
                return body
            seen.append((detail.get("queryExecutionId"), detail.get("currentState")))
    raise AssertionError(
        f"{description}: no {_DETAIL_TYPE} event with queryExecutionId={query_execution_id!r} and "
        f"currentState={current_state!r} arrived within {timeout_s}s; the events seen were {seen!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:eventing", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Athena Query State Change events reach SQS: the SUCCEEDED event has no athenaError block, and
    the missing-table FAILED event's athenaError matches GetQueryExecution for the same execution.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/athena-events.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-xsvc-athena-data-")

    marker = ctx.unique_name("").replace("-", "")[:12]
    body = f"1,evt-{marker}\n".encode()
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=body)

    wg = ctx.unique_name("sim2real-xsvc-athena-wg-evt-")
    athena.create_work_group(
        Name=wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": out},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": "athena-query-state-change-event"},
              {"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    queue_url, queue_arn = _queue(ctx)
    rule = _rule_to_queue(ctx, wg, queue_url, queue_arn)
    targets = ctx.client("events").list_targets_by_rule(Rule=rule)["Targets"]
    assert [t["Arn"] for t in targets] == [queue_arn], (
        f"the rule must be observably wired to the queue before any delivery is concluded from "
        f"it: ListTargetsByRule for {rule!r} returned {targets!r}, expected {queue_arn!r}")

    database = ctx.unique_name("sim2real-xsvc-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-xsvc-tbl-").replace("-", "_")
    # DDL runs OUTSIDE the workgroup so the rule (narrowed to that workgroup) sees only the two
    # DML executions this check is about.
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'")

    # A query that succeeds: the delivered event must describe it and carry no error block.
    ok_qid = _start_query(
        athena, None, f"SELECT name FROM {_dml_name(database, table)} ORDER BY name",
        workgroup=wg, database=database)
    ok_state = _wait_terminal(athena, ok_qid)
    assert ok_state == "SUCCEEDED", (
        f"the positive query must SUCCEED so the SUCCEEDED event exists to be judged; got "
        f"{ok_state!r}")
    ok_event = _collect_event(ctx, queue_url, query_execution_id=ok_qid,
                             current_state="SUCCEEDED",
                             description="the SUCCEEDED state-change event")
    assert ok_event["source"] == _SOURCE, (
        f"the event source must be {_SOURCE!r}, got {ok_event['source']!r}")
    assert ok_event["detail-type"] == _DETAIL_TYPE, (
        f"the detail-type must be {_DETAIL_TYPE!r}, got {ok_event['detail-type']!r}")
    assert ok_event["account"] == account_id, (
        f"the event must be attributed to this account ({account_id}), got "
        f"{ok_event['account']!r}")
    assert ok_event["region"] == ctx.region, (
        f"the event must be attributed to {ctx.region!r}, got {ok_event['region']!r}")
    ok_detail = ok_event["detail"]
    assert ok_detail["workgroupName"] == wg, (
        f"the event must name the workgroup the query ran in ({wg!r}), got "
        f"{ok_detail['workgroupName']!r}")
    assert ok_detail["statementType"] == "DML", (
        f"a SELECT is a DML statement, so detail.statementType must be 'DML', got "
        f"{ok_detail['statementType']!r}")
    assert ok_detail["previousState"] == "RUNNING", (
        f"a query that reached SUCCEEDED transitioned out of RUNNING, so detail.previousState must "
        f"be 'RUNNING', got {ok_detail['previousState']!r}")
    assert str(ok_detail["sequenceNumber"]).isdigit(), (
        f"detail.sequenceNumber must be a decimal counter, got "
        f"{ok_detail['sequenceNumber']!r}")
    assert "athenaError" not in ok_detail, (
        f"the athenaError block appears ONLY when currentState is FAILED, so a SUCCEEDED event "
        f"must not carry one; got {ok_detail!r}")

    # A query that fails on a missing table: the event's classification must agree with the API's.
    missing = ctx.unique_name("sim2real-xsvc-absent-").replace("-", "_")
    bad_qid = _start_query(
        athena, None, f"SELECT name FROM {_dml_name(database, missing)}",
        workgroup=wg, database=database)
    bad_state = _wait_terminal(athena, bad_qid)
    assert bad_state == "FAILED", (
        f"a SELECT over the never-created table {missing!r} must reach FAILED, got {bad_state!r}")
    api_error = athena.get_query_execution(QueryExecutionId=bad_qid)["QueryExecution"]["Status"][
        "AthenaError"]
    bad_event = _collect_event(ctx, queue_url, query_execution_id=bad_qid, current_state="FAILED",
                              description="the FAILED state-change event")
    bad_detail = bad_event["detail"]
    assert bad_detail["workgroupName"] == wg, (
        f"the failure event must name the same workgroup ({wg!r}), got "
        f"{bad_detail['workgroupName']!r}")
    event_error = bad_detail["athenaError"]
    assert int(event_error["errorCategory"]) == 2, (
        f"a query naming a table that does not exist is a USER error, so the published "
        f"errorCategory must be 2 (1=System, 2=User, 3=Other); got {event_error!r}")
    assert int(event_error["errorCategory"]) == int(api_error["ErrorCategory"]), (
        f"the published classification must agree with the one GetQueryExecution reports for the "
        f"same execution: event {event_error['errorCategory']!r} vs API "
        f"{api_error['ErrorCategory']!r}")
    assert int(event_error["errorType"]) == int(api_error["ErrorType"]), (
        f"the published errorType must agree with the API's for the same execution: event "
        f"{event_error['errorType']!r} vs API {api_error['ErrorType']!r}")
    assert event_error["retryable"] is False, (
        f"a missing table cannot be fixed by resubmitting, so retryable must be False, got "
        f"{event_error!r}")
    assert event_error["errorMessage"].strip(), (
        f"the published error must carry a non-empty errorMessage, got {event_error!r}")
    assert event_error["errorMessage"] == api_error["ErrorMessage"], (
        f"the published errorMessage must be the same text GetQueryExecution reports for the same "
        f"execution: event {event_error['errorMessage']!r} vs API "
        f"{api_error['ErrorMessage']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
