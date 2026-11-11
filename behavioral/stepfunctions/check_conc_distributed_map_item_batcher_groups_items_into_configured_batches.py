"""conc-distributed-map-item-batcher-groups-items-into-configured-batches."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-distributed-map-item-batcher-groups-items-into-configured-batches"
GROUP = 'distributed_map'
SERVICES = ['stepfunctions']

_N_ITEMS = 23
_PER_BATCH = 5
_ITEMS_KEY = "items.json"
_LABEL = "sim2real-batch-input"


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2", "cap:c3")
def run(ctx) -> None:
    """An ItemBatcher with MaxItemsPerBatch=5 over 23 S3 items hands children batches of 5, 5, 5,
    5 and 3, every item in exactly one batch, with BatchInput merged into each, as recorded by the
    children themselves in DynamoDB.
    """
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket = _create_bucket(ctx)
    ids = [f"b-{i:02d}" for i in range(_N_ITEMS)]
    s3.put_object(Bucket=bucket, Key=_ITEMS_KEY,
                  Body=json.dumps([{"id": i} for i in ids]).encode())
    table, table_arn = _create_table(ctx)
    role_arn = _create_role(ctx, account_id, bucket, table_arn)
    definition = {
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Map",
                "MaxConcurrency": 10,
                "ItemReader": {
                    "Resource": "arn:aws:states:::s3:getObject",
                    "ReaderConfig": {"InputType": "JSON"},
                    "Parameters": {"Bucket": bucket, "Key": _ITEMS_KEY},
                },
                "ItemBatcher": {
                    "MaxItemsPerBatch": _PER_BATCH,
                    "BatchInput": {"run.$": "$.run", "label": _LABEL},
                },
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Record",
                    "States": {
                        "Record": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::dynamodb:updateItem",
                            "Parameters": {
                                "TableName": table,
                                "Key": {"pk": {"S.$": (
                                    "States.Format('{}#batch#{}', $.BatchInput.run, "
                                    "$$.Execution.Name)")}},
                                "UpdateExpression": "ADD hits :one SET members = :m, n = :n, "
                                                    "label = :l",
                                "ExpressionAttributeValues": {
                                    ":one": {"N": "1"},
                                    ":m": {"S.$": "States.JsonToString($.Items)"},
                                    ":n": {"N.$": "States.Format('{}', States.ArrayLength($.Items))"},
                                    ":l": {"S.$": "$.BatchInput.label"},
                                },
                            },
                            "ResultPath": None, "Retry": _DDB_RETRY, "End": True,
                        },
                    },
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    exe, run_tag = _run_to_terminal(ctx, sm_arn, {}, timeout_s=200.0)
    assert exe["status"] == "SUCCEEDED", (
        f'execution was {exe["status"]!r}: {exe.get("error")!r} {exe.get("cause")!r}'
    )

    rows = list(_ledger(ctx, table, run_tag).values())
    batches = [[m["id"] for m in json.loads(r["members"]["S"])] for r in rows]
    sizes = sorted(len(b) for b in batches)
    assert sizes == [3, 5, 5, 5, 5], (
        f"the children received batches of sizes {sizes!r}; MaxItemsPerBatch={_PER_BATCH!r} "
        f"over {_N_ITEMS!r} items packs into [3, 5, 5, 5, 5]"
    )
    flat = [i for b in batches for i in b]
    assert sorted(flat) == ids, (
        f"the batches cover {len(flat)!r} item slots over {len(set(flat))!r} distinct ids; every "
        f"one of the {_N_ITEMS!r} items must appear in exactly one batch"
    )
    counted = sorted(int(r["n"]["N"]) for r in rows)
    assert counted == sizes, (
        f"the children's own ArrayLength of $.Items was {counted!r}, the recorded members {sizes!r}"
    )
    labels = {r["label"]["S"] for r in rows}
    assert labels == {_LABEL}, f"BatchInput reached the children as {labels!r}"
    hits = sorted(int(r["hits"]["N"]) for r in rows)
    assert hits == [1] * len(rows), f"a batch child recorded more than once: hits {hits!r}"


# ===== helpers =====
_DDB_RETRY = [{
    # IAM propagation of the just-created role only: an AccessDenied write had no effect, so
    # retrying it cannot double-count a ledger row.
    "ErrorEquals": ["DynamoDB.AmazonDynamoDBException"],
    "IntervalSeconds": 2, "MaxAttempts": 5, "BackoffRate": 1.5,
}]


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


def _run_to_terminal(ctx, sm_arn, extra_input, *, timeout_s, propagation_s=120.0):
    """Start an execution under a fresh run tag and poll it to terminal.

    A fresh execution is started only when the failure is the IAM-propagation race; every
    attempt writes under its own run tag, so a discarded attempt's rows never count.
    """
    sfn = ctx.client("stepfunctions")
    desc = run_tag = None
    deadline = _deadline(ctx, propagation_s)
    while True:
        run_tag = ctx.unique_name("run-")
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps({"run": run_tag, **extra_input}),
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


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on an already-terminal execution, so ExecutionDoesNotExist is
        # the only expected failure here; anything else is a real teardown failure and must raise.
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
    return runs[0]


def _list_executions(ctx, **filters):
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"maxResults": 100, **filters}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_executions(**kwargs)
        out.extend(resp["executions"])
        token = resp.get("nextToken")
        if not token:
            return out


def _deadline(ctx, timeout_s):
    """A monotonic deadline ``timeout_s`` away, capped by the check's remaining run time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
