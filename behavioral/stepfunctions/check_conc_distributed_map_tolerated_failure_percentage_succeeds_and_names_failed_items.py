"""conc-distributed-map-tolerated-failure-percentage-succeeds-and-names-failed-items."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-distributed-map-tolerated-failure-percentage-succeeds-and-names-failed-items"
GROUP = 'distributed_map'
SERVICES = ['stepfunctions']

_N_ITEMS = 40
_FAIL_IDS = ["item-13", "item-31"]           # 2 of 40 = 5%
_OK_IDS = [f"item-{i:02d}" for i in range(_N_ITEMS) if f"item-{i:02d}" not in _FAIL_IDS]
_ITEMS_KEY = "items.json"
_RESULT_PREFIX = "results"
_TOLERANCE = 10


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2", "cap:c3")
def run(ctx) -> None:
    """ToleratedFailurePercentage=10 over 40 items with 2 failing (5%) SUCCEEDS and names exactly
    those 2 as failed in the ResultWriter FAILED output, DescribeMapRun and the child listing;
    the other 38 each write one DynamoDB row, the failed 2 write none."""
    s3 = ctx.client("s3")
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key=_ITEMS_KEY, Body=json.dumps(
        [{"id": f"item-{i:02d}", "fail": f"item-{i:02d}" in _FAIL_IDS} for i in range(_N_ITEMS)]
    ).encode())
    table, table_arn = _create_table(ctx)
    role_arn = _create_role(ctx, account_id, bucket, table_arn)
    sm_arn = _create_state_machine(ctx, _definition(bucket, table), role_arn)

    exe, run_tag = _run_to_terminal(ctx, sm_arn, table, tolerance=_TOLERANCE, timeout_s=220.0)
    assert exe["status"] == "SUCCEEDED", (
        f"at ToleratedFailurePercentage={_TOLERANCE} with 5% failing the run was "
        f'{exe["status"]!r}: {exe.get("error")!r} {exe.get("cause")!r}'
    )

    # Effect present for the 38, absent for the 2.
    rows = _item_rows(ctx, table, run_tag)
    assert rows == set(_OK_IDS), (
        f"ledger rows: missing {sorted(set(_OK_IDS) - rows)!r}, unexpected "
        f"{sorted(rows - set(_OK_IDS))!r} (the failed items {_FAIL_IDS!r} must write nothing)"
    )

    map_run_arn = _one_map_run(ctx, exe["executionArn"])
    mr = sfn.describe_map_run(mapRunArn=map_run_arn)
    assert mr["toleratedFailurePercentage"] == _TOLERANCE, (
        f'DescribeMapRun reports toleratedFailurePercentage {mr["toleratedFailurePercentage"]!r}'
    )
    counts = mr["itemCounts"]
    assert (counts["total"], counts["succeeded"], counts["failed"]) == (
        _N_ITEMS, len(_OK_IDS), len(_FAIL_IDS)
    ), f"DescribeMapRun itemCounts {counts!r}"

    # The failed items are NAMED in the result the service wrote to S3.
    writer = json.loads(exe["output"])["ResultWriterDetails"]
    manifest = json.loads(s3.get_object(Bucket=writer["Bucket"], Key=writer["Key"])["Body"].read())
    failed_records = []
    for f in manifest["ResultFiles"]["FAILED"]:
        failed_records.extend(json.loads(
            s3.get_object(Bucket=writer["Bucket"], Key=f["Key"])["Body"].read()))
    named = sorted(json.loads(r["Input"])["id"] for r in failed_records)
    assert named == sorted(_FAIL_IDS), (
        f"the ResultWriter FAILED output names {named!r}, expected {sorted(_FAIL_IDS)!r}"
    )
    errors = {r.get("Error") for r in failed_records}
    assert errors == {"Deliberate.ItemFailure"}, (
        f"the FAILED records carry errors {errors!r}, expected the planted Deliberate.ItemFailure"
    )
    succeeded_ids = []
    for f in manifest["ResultFiles"]["SUCCEEDED"]:
        succeeded_ids.extend(json.loads(rec["Input"])["id"] for rec in json.loads(
            s3.get_object(Bucket=writer["Bucket"], Key=f["Key"])["Body"].read()))
    assert sorted(succeeded_ids) == sorted(_OK_IDS), (
        f"the SUCCEEDED output holds {len(succeeded_ids)!r} records, expected the "
        f"{len(_OK_IDS)!r} healthy items once each"
    )

    # And the child-execution listing agrees: the FAILED children are the planted two.
    failed_children = _list_children(ctx, map_run_arn, "FAILED")
    child_ids = sorted(
        json.loads(sfn.describe_execution(executionArn=c["executionArn"])["input"])["id"]
        for c in failed_children
    )
    assert child_ids == sorted(_FAIL_IDS), (
        f"ListExecutions(mapRunArn, FAILED) returned children for {child_ids!r}"
    )


def _list_children(ctx, map_run_arn, status):
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"mapRunArn": map_run_arn, "statusFilter": status, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_executions(**kwargs)
        out.extend(resp["executions"])
        token = resp.get("nextToken")
        if not token:
            return out


def _definition(bucket, table):
    ddb_retry = [{
        # IAM propagation of the just-created role only: an AccessDenied call had no effect,
        # so retrying it cannot double-count. The deliberate failure is a Fail state, not this.
        "ErrorEquals": ["DynamoDB.AmazonDynamoDBException"],
        "IntervalSeconds": 2, "MaxAttempts": 5, "BackoffRate": 1.5,
    }]
    return {
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Map",
                "MaxConcurrency": _N_ITEMS,
                "ToleratedFailurePercentage": _TOLERANCE,
                "ItemReader": {
                    "Resource": "arn:aws:states:::s3:getObject",
                    "ReaderConfig": {"InputType": "JSON"},
                    "Parameters": {"Bucket": bucket, "Key": _ITEMS_KEY},
                },
                "ItemSelector": {
                    "id.$": "$$.Map.Item.Value.id", "fail.$": "$$.Map.Item.Value.fail",
                    "run.$": "$.run", "tries": {"n": 0},
                },
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Route",
                    "States": {
                        "Route": {
                            "Type": "Choice",
                            "Choices": [{"Variable": "$.fail", "BooleanEquals": True,
                                         "Next": "Poll"}],
                            "Default": "Record",
                        },
                        "Record": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::dynamodb:updateItem",
                            "Parameters": {
                                "TableName": table,
                                "Key": {"pk": {"S.$": "States.Format('{}#item#{}', $.run, $.id)"}},
                                "UpdateExpression": "ADD hits :one",
                                "ExpressionAttributeValues": {":one": {"N": "1"}},
                            },
                            "ResultPath": None, "Retry": ddb_retry, "Next": "Done",
                        },
                        "Done": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::dynamodb:updateItem",
                            "Parameters": {
                                "TableName": table,
                                "Key": {"pk": {"S.$": "States.Format('{}#done', $.run)"}},
                                "UpdateExpression": "ADD n :one",
                                "ExpressionAttributeValues": {":one": {"N": "1"}},
                            },
                            "ResultPath": None, "Retry": ddb_retry, "End": True,
                        },
                        # The barrier: a failing item fails only once every healthy item is done.
                        "Poll": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::dynamodb:getItem",
                            "Parameters": {
                                "TableName": table, "ConsistentRead": True,
                                "Key": {"pk": {"S.$": "States.Format('{}#done', $.run)"}},
                            },
                            "ResultSelector": {"n.$": "States.StringToJson($.Item.n.N)"},
                            "ResultPath": "$.done", "Retry": ddb_retry, "Next": "Gate",
                        },
                        "Gate": {
                            "Type": "Choice",
                            "Choices": [
                                {"Variable": "$.done.n", "NumericGreaterThanEquals": len(_OK_IDS),
                                 "Next": "Boom"},
                                {"Variable": "$.tries.n", "NumericGreaterThanEquals": 60,
                                 "Next": "Stuck"},
                            ],
                            "Default": "Nap",
                        },
                        "Nap": {"Type": "Wait", "Seconds": 2, "Next": "Tick"},
                        "Tick": {
                            "Type": "Pass",
                            "Parameters": {"n.$": "States.MathAdd($.tries.n, 1)"},
                            "ResultPath": "$.tries", "Next": "Poll",
                        },
                        "Boom": {"Type": "Fail", "Error": "Deliberate.ItemFailure",
                                 "Cause": "this item is planted to fail"},
                        "Stuck": {"Type": "Fail", "Error": "Barrier.NeverReleased",
                                  "Cause": "the healthy items never all reported done"},
                    },
                },
                "ResultWriter": {
                    "Resource": "arn:aws:states:::s3:putObject",
                    "Parameters": {"Bucket": bucket, "Prefix": _RESULT_PREFIX},
                },
                "End": True,
            }
        },
    }


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-dmap-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-dmap-")
    arn = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_tags_kv(),
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return name, arn


def _ledger(ctx, table, run_tag):
    """Every ledger row of this run, strongly consistent and paginated."""
    ddb = ctx.client("dynamodb")
    rows, kwargs = {}, {
        "TableName": table, "ConsistentRead": True,
        "FilterExpression": "begins_with(pk, :p)",
        "ExpressionAttributeValues": {":p": {"S": f"{run_tag}#"}},
    }
    while True:
        resp = ddb.scan(**kwargs)
        rows.update({it["pk"]["S"]: it for it in resp["Items"]})
        if "LastEvaluatedKey" not in resp:
            return rows
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _item_rows(ctx, table, run_tag):
    rows = _ledger(ctx, table, run_tag)
    items = {pk.split("#item#", 1)[1]: int(r["hits"]["N"]) for pk, r in rows.items()
             if "#item#" in pk}
    assert all(h == 1 for h in items.values()), f"items processed more than once: {items!r}"
    return set(items)


def _done_count(ctx, table, run_tag):
    item = ctx.client("dynamodb").get_item(
        TableName=table, Key={"pk": {"S": f"{run_tag}#done"}}, ConsistentRead=True)["Item"]
    return int(item["n"]["N"])


def _create_role(ctx, account_id, bucket, table_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-dmaprole-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn distributed-map execution role", Tags=_tags_kv(),
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    statements = [
        {"Effect": "Allow", "Action": ["states:StartExecution"],
         "Resource": f"arn:aws:states:{ctx.region}:{account_id}:stateMachine:*"},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": f"arn:aws:states:{ctx.region}:{account_id}:execution:*:*"},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
         "Resource": f"arn:aws:s3:::{bucket}/*"},
        {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
        {"Effect": "Allow", "Action": ["dynamodb:UpdateItem", "dynamodb:GetItem"],
         "Resource": table_arn},
    ]
    iam.put_role_policy(
        RoleName=role_name, PolicyName=f"{role_name}-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-dmap-")
    deadline = _deadline(ctx, 90.0)
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume", "cannot be assumed", "sts:AssumeRole",
    "States.Permissions", "AccessDenied",
)


def _run_to_terminal(ctx, sm_arn, table, *, tolerance, timeout_s, propagation_s=120.0):
    """Start an execution under a fresh run tag and poll it to terminal.

    The barrier's counter is seeded to 0 first, so the failing child's GetItem always finds
    it. A fresh execution is started only when the failure is the IAM-propagation race; every
    attempt writes under its own run tag, so a discarded attempt's rows never count.
    """
    sfn = ctx.client("stepfunctions")
    ddb = ctx.client("dynamodb")
    desc = run_tag = None
    deadline = _deadline(ctx, propagation_s)
    while True:
        run_tag = ctx.unique_name("run-")
        ddb.put_item(TableName=table, Item={"pk": {"S": f"{run_tag}#done"}, "n": {"N": "0"}})
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps({"run": run_tag, "tolerance": tolerance}),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc, run_tag
        if time.monotonic() >= deadline:
            return desc, run_tag
        time.sleep(2)


def _wait_terminal(ctx, exec_arn, *, timeout_s, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _deadline(ctx, timeout_s):
    """A monotonic deadline ``timeout_s`` away, capped by the check's remaining run time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _one_map_run(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    runs, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_map_runs(**kwargs)
        runs.extend(resp["mapRuns"])
        token = resp.get("nextToken")
        if not token:
            break
    assert len(runs) == 1, f"expected exactly one map run for {exec_arn!r}, got {runs!r}"
    return runs[0]["mapRunArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
