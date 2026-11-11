"""conc-distributed-map-200-s3-objects-processed-once-under-concurrency-cap."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-distributed-map-200-s3-objects-processed-once-under-concurrency-cap"
GROUP = 'distributed_map'
SERVICES = ['stepfunctions']

_N_OBJECTS = 200
_MAX_CONCURRENCY = 5
_INPUT_PREFIX = "input/"
_RESULT_PREFIX = "results"


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2", "cap:c3")
def run(ctx) -> None:
    """A Distributed Map over 200 S3 objects at MaxConcurrency=5 processes every object exactly
    once, never has more than 5 children in flight, and DescribeMapRun and ResultWriter agree.
    """
    s3 = ctx.client("s3")
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    keys = [f"{_INPUT_PREFIX}obj-{i:04d}.txt" for i in range(_N_OBJECTS)]
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda k: s3.put_object(Bucket=bucket, Key=k, Body=k.encode()), keys))
    listed = _list_keys(ctx, bucket, _INPUT_PREFIX)
    assert listed == set(keys), (
        f"setup: {len(listed)!r} input objects listed, expected {_N_OBJECTS!r}"
    )

    table, table_arn = _create_table(ctx)
    role_arn = _create_role(ctx, account_id, bucket, table_arn)

    ddb_retry = [{
        # Absorbs IAM propagation of the just-created role only; an AccessDenied write never
        # happened, so retrying it cannot double-count the ledger.
        "ErrorEquals": ["DynamoDB.AmazonDynamoDBException"],
        "IntervalSeconds": 2, "MaxAttempts": 5, "BackoffRate": 1.5,
    }]
    definition = {
        "Comment": "every child records its item once and the in-flight gauge it observed",
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Map",
                "MaxConcurrency": _MAX_CONCURRENCY,
                "ItemReader": {
                    "Resource": "arn:aws:states:::s3:listObjectsV2",
                    "Parameters": {"Bucket": bucket, "Prefix": _INPUT_PREFIX},
                },
                "ItemSelector": {"key.$": "$$.Map.Item.Value.Key", "run.$": "$.run"},
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Enter",
                    "States": {
                        "Enter": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::dynamodb:updateItem",
                            "Parameters": {
                                "TableName": table,
                                "Key": {"pk": {"S.$": "States.Format('{}#gauge', $.run)"}},
                                "UpdateExpression": "ADD inflight :d",
                                "ExpressionAttributeValues": {":d": {"N": "1"}},
                                "ReturnValues": "UPDATED_NEW",
                            },
                            "ResultSelector": {"n.$": "$.Attributes.inflight.N"},
                            "ResultPath": "$.enter",
                            "Retry": ddb_retry,
                            "Next": "Record",
                        },
                        "Record": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::dynamodb:updateItem",
                            "Parameters": {
                                "TableName": table,
                                "Key": {"pk": {"S.$": "States.Format('{}#item#{}', $.run, $.key)"}},
                                "UpdateExpression": "ADD hits :one SET seen = :seen, ex = :ex",
                                "ExpressionAttributeValues": {
                                    ":one": {"N": "1"},
                                    ":seen": {"N.$": "$.enter.n"},
                                    ":ex": {"S.$": "$$.Execution.Id"},
                                },
                            },
                            "ResultPath": None,
                            "Retry": ddb_retry,
                            "Next": "Hold",
                        },
                        "Hold": {"Type": "Wait", "Seconds": 1, "Next": "Leave"},
                        "Leave": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::dynamodb:updateItem",
                            "Parameters": {
                                "TableName": table,
                                "Key": {"pk": {"S.$": "States.Format('{}#gauge', $.run)"}},
                                "UpdateExpression": "ADD inflight :d",
                                "ExpressionAttributeValues": {":d": {"N": "-1"}},
                            },
                            "ResultPath": None,
                            "Retry": ddb_retry,
                            "Next": "Out",
                        },
                        "Out": {"Type": "Pass", "Parameters": {"key.$": "$.key"}, "End": True},
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
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    exe, run_tag = _run_to_terminal(ctx, sm_arn, timeout_s=270.0)
    assert exe["status"] == "SUCCEEDED", (
        f'execution was {exe["status"]!r}: {exe.get("error")!r} {exe.get("cause")!r}'
    )

    # --- exactly-once processing, from the ledger the children wrote ---
    # Each child does an atomic ADD of 1 to its item's row, so a re-processed item shows hits=2.
    rows = _ledger(ctx, table, run_tag)
    items = {pk.split("#item#", 1)[1]: r for pk, r in rows.items() if "#item#" in pk}
    assert set(items) == set(keys), (
        f"the ledger holds {len(items)!r} distinct items, expected {_N_OBJECTS!r}; missing "
        f"{sorted(set(keys) - set(items))[:5]!r}, unexpected {sorted(set(items) - set(keys))[:5]!r}"
    )
    dupes = {k: int(r["hits"]["N"]) for k, r in items.items() if int(r["hits"]["N"]) != 1}
    assert dupes == {}, f"items processed other than exactly once (key: hits): {dupes!r}"
    child_execs = {r["ex"]["S"] for r in items.values()}
    assert len(child_execs) == _N_OBJECTS, (
        f"{_N_OBJECTS!r} items were recorded by {len(child_execs)!r} distinct child "
        f"executions; without an ItemBatcher every item gets its own child"
    )

    # --- the concurrency cap, from the gauge values the children themselves observed ---
    # The max child-observed gauge can only be <= the true concurrency, so "<= cap" needs no clock.
    # MaxConcurrency is an upper bound only, so no minimum parallelism is asserted.
    seen = [int(r["seen"]["N"]) for r in items.values()]
    high_water = max(seen)
    assert high_water <= _MAX_CONCURRENCY, (
        f"a child observed {high_water!r} children in flight, above MaxConcurrency="
        f"{_MAX_CONCURRENCY!r}; observed-value histogram {sorted(set(seen))!r}"
    )
    gauge = int(rows[f"{run_tag}#gauge"]["inflight"]["N"])
    assert gauge == 0, (
        f"every child incremented and decremented the gauge once, yet it rests at {gauge!r}"
    )

    # --- the map run's own accounting agrees with the ledger ---
    map_run_arn = _one_map_run(ctx, exe["executionArn"])
    mr = sfn.describe_map_run(mapRunArn=map_run_arn)
    assert mr["maxConcurrency"] == _MAX_CONCURRENCY, (
        f'DescribeMapRun reports maxConcurrency {mr["maxConcurrency"]!r}'
    )
    counts = mr["itemCounts"]
    assert (counts["total"], counts["succeeded"], counts["failed"]) == (_N_OBJECTS, _N_OBJECTS, 0), (
        f"DescribeMapRun itemCounts {counts!r} disagree with the ledger's {len(items)!r} items"
    )
    # The map's own processed-and-written count. (There is no ProcessedItemCount field on the
    # ResultWriter path — its output is MapRunArn + ResultWriterDetails — so this is the count.)
    assert counts["resultsWritten"] == len(items), (
        f'DescribeMapRun says {counts["resultsWritten"]!r} results were written; the ledger '
        f"holds {len(items)!r} processed items"
    )

    # --- the ResultWriter output in S3 names the same 200 items ---
    output = json.loads(exe["output"])
    assert output["MapRunArn"] == map_run_arn, (
        f'the execution output names map run {output["MapRunArn"]!r}, ListMapRuns {map_run_arn!r}'
    )
    writer = output["ResultWriterDetails"]
    manifest = json.loads(s3.get_object(Bucket=writer["Bucket"], Key=writer["Key"])["Body"].read())
    assert (manifest["MapRunArn"], manifest["ResultFiles"]["FAILED"],
            manifest["ResultFiles"]["PENDING"]) == (map_run_arn, [], []), (
        f'the manifest is for {manifest["MapRunArn"]!r} with FAILED '
        f'{manifest["ResultFiles"]["FAILED"]!r} PENDING {manifest["ResultFiles"]["PENDING"]!r}'
    )
    written = []
    for f in manifest["ResultFiles"]["SUCCEEDED"]:
        body = s3.get_object(Bucket=writer["Bucket"], Key=f["Key"])["Body"].read()
        written.extend(json.loads(rec["Output"])["key"] for rec in json.loads(body))
    assert len(written) == _N_OBJECTS and set(written) == set(items), (
        f"the ResultWriter wrote {len(written)!r} records over {len(set(written))!r} keys; the "
        f"ledger holds {len(items)!r}; symmetric difference "
        f"{sorted(set(written) ^ set(items))[:5]!r}"
    )


# ===== helpers =====
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


def _list_keys(ctx, bucket, prefix):
    s3 = ctx.client("s3")
    out = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.update(o["Key"] for o in page.get("Contents", []))
    return out


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


def _run_to_terminal(ctx, sm_arn, *, timeout_s, propagation_s=120.0):
    """Start an execution under a fresh run tag and poll it to terminal.

    A fresh execution is started only when the failure is the IAM-propagation race; every
    attempt writes under its own run tag, so a discarded attempt's ledger rows can never be
    counted against the kept one.
    """
    sfn = ctx.client("stepfunctions")
    desc = run_tag = None
    deadline = _deadline(ctx, propagation_s)
    while True:
        run_tag = ctx.unique_name("run-")
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps({"run": run_tag}),
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
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
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


def _deadline(ctx, timeout_s):
    """A monotonic deadline ``timeout_s`` away, capped by the check's remaining run time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
