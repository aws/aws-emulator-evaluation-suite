"""sfn-redrive-of-a-partly-failed-map-run-reruns-only-the-failed-items."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-redrive-of-a-partly-failed-map-run-reruns-only-the-failed-items"
GROUP = 'distributed_map'
SERVICES = ['s3', 'stepfunctions']

_ITEMS_KEY = "input/items.json"
_GATE_PREFIX = "gates/"
_WRITE_PREFIX = "writes/"
_OK_IDS = [f"item-{i:02d}" for i in range(6)]
_FAIL_IDS = [f"item-{i:02d}" for i in range(6, 9)]


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """Redriving a Distributed Map run in which 3 of 9 children failed re-runs exactly those 3
    from the step that failed, and does not re-run the 6 that already succeeded (per-item S3
    write counts).
    """
    s3 = ctx.client("s3")
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    # `slow` only sequences the run; the last three items have no gate object, so their child's
    # first task fails and their write never happens.
    s3.put_object(
        Bucket=bucket,
        Key=_ITEMS_KEY,
        Body=json.dumps(
            [{"itemId": i, "slow": False} for i in _OK_IDS]
            + [{"itemId": i, "slow": True} for i in _FAIL_IDS]
        ).encode(),
    )
    for item_id in _OK_IDS:
        s3.put_object(Bucket=bucket, Key=f"{_GATE_PREFIX}{item_id}.json", Body=b"{}")

    role_arn = _create_distributed_map_role(ctx, bucket, account_id)

    definition = {
        "Comment": "each child reads its gate object, then writes its own S3 object",
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Map",
                "MaxConcurrency": len(_OK_IDS) + len(_FAIL_IDS),
                "ItemReader": {
                    "Resource": "arn:aws:states:::s3:getObject",
                    "ReaderConfig": {"InputType": "JSON"},
                    "Parameters": {"Bucket": bucket, "Key": _ITEMS_KEY},
                },
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Sort",
                    "States": {
                        # The gate-less children hold for 10 s before failing, so all six
                        # healthy children finish before the default zero-failure tolerance
                        # stops the map run dispatching.
                        "Sort": {
                            "Type": "Choice",
                            "Choices": [
                                {"Variable": "$.slow", "BooleanEquals": True, "Next": "Hold"}
                            ],
                            "Default": "Gate",
                        },
                        "Hold": {"Type": "Wait", "Seconds": 10, "Next": "Gate"},
                        "Gate": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::aws-sdk:s3:getObject",
                            "Parameters": {
                                "Bucket": bucket,
                                "Key.$": (
                                    "States.Format('" + _GATE_PREFIX + "{}.json', $.itemId)"
                                ),
                            },
                            "ResultSelector": {"gateRead": True},
                            "ResultPath": "$.gate",
                            # Absorbs IAM propagation only: a just-created role can deny its own
                            # S3 calls for a few seconds. NoSuchKeyException (the induced failure)
                            # is not retried.
                            "Retry": [{
                                "ErrorEquals": ["S3.AccessDeniedException"],
                                "IntervalSeconds": 1,
                                "MaxAttempts": 5,
                                "BackoffRate": 2.0,
                            }],
                            "Next": "Write",
                        },
                        "Write": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                            "Parameters": {
                                "Bucket": bucket,
                                "Key.$": (
                                    "States.Format('" + _WRITE_PREFIX
                                    + "{}/{}.json', $.itemId, States.UUID())"
                                ),
                                "Body.$": "$.itemId",
                            },
                            "Retry": [{
                                "ErrorEquals": ["S3.AccessDeniedException"],
                                "IntervalSeconds": 1,
                                "MaxAttempts": 5,
                                "BackoffRate": 2.0,
                            }],
                            "End": True,
                        },
                    },
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    first = _run_to_terminal(ctx, sm_arn, {}, bucket, timeout_s=240.0)
    assert first["status"] == "FAILED", (
        f'the first execution was {first["status"]!r}, expected FAILED so that it is '
        f'redrivable: {first.get("error")!r} {first.get("cause")!r}'
    )
    map_run_arn = _one_map_run(ctx, first["executionArn"])
    first_counters = sfn.describe_map_run(mapRunArn=map_run_arn)["itemCounts"]
    assert (first_counters["succeeded"], first_counters["failed"]) == (
        len(_OK_IDS), len(_FAIL_IDS)
    ), (
        f"the first map run counted {first_counters!r}, expected "
        f"{len(_OK_IDS)!r} succeeded and {len(_FAIL_IDS)!r} failed; the execution's own "
        f"error/cause was {first.get('error')!r} {first.get('cause')!r}, and a non-gate child "
        f"failure looks like {_a_child_failure(ctx, map_run_arn)!r}"
    )

    counts_before = _write_counts(ctx, bucket)
    assert counts_before == {i: 1 for i in _OK_IDS}, (
        f"before the redrive exactly the six healthy children should have written once and the "
        f"three gate-less ones not at all; the counts were {counts_before!r}"
    )

    # Give the three failed items their missing gate object; nothing else changes.
    for item_id in _FAIL_IDS:
        s3.put_object(Bucket=bucket, Key=f"{_GATE_PREFIX}{item_id}.json", Body=b"{}")

    sfn.redrive_execution(executionArn=first["executionArn"])
    second = _wait_terminal(ctx, first["executionArn"], timeout_s=240.0)
    assert second["status"] == "SUCCEEDED", (
        f'the redriven execution was {second["status"]!r}: '
        f'{second.get("error")!r} {second.get("cause")!r}'
    )
    assert second["redriveCount"] == 1, (
        f'redriveCount is {second["redriveCount"]!r} after exactly one redrive'
    )

    counts_after = _write_counts(ctx, bucket)
    assert {i: counts_after.get(i) for i in _FAIL_IDS} == {i: 1 for i in _FAIL_IDS}, (
        f"the three failed children should have re-run and written once each: their write "
        f"counts are {[(i, counts_after.get(i)) for i in _FAIL_IDS]!r}"
    )
    assert {i: counts_after.get(i) for i in _OK_IDS} == {i: 1 for i in _OK_IDS}, (
        f"the six children that already succeeded were re-executed by the redrive — their "
        f"write counts are {[(i, counts_after.get(i)) for i in _OK_IDS]!r}, expected 1 each"
    )
    assert set(counts_after) == set(_OK_IDS + _FAIL_IDS), (
        f"items missing from the output entirely: "
        f"{sorted(set(_OK_IDS + _FAIL_IDS) - set(counts_after))!r}"
    )

    second_counters = sfn.describe_map_run(mapRunArn=map_run_arn)["itemCounts"]
    assert (second_counters["succeeded"], second_counters["failed"]) == (
        len(_OK_IDS) + len(_FAIL_IDS), 0
    ), (
        f"after the redrive the map run should account for all "
        f"{len(_OK_IDS) + len(_FAIL_IDS)!r} items as succeeded; it reports {second_counters!r}"
    )


# ===== helpers =====
def _write_counts(ctx, bucket):
    """How many objects each item id wrote, from a paginated listing of the write prefix."""
    counts = {}
    for key in _list_keys(ctx, bucket, _WRITE_PREFIX):
        item_id = key[len(_WRITE_PREFIX):].split("/", 1)[0]
        counts[item_id] = counts.get(item_id, 0) + 1
    return counts


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-sfnmap-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _list_keys(ctx, bucket, prefix):
    s3 = ctx.client("s3")
    out = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.update(o["Key"] for o in page.get("Contents", []))
    return out


def _create_distributed_map_role(ctx, bucket, account_id, *, extra=()):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn distributed-map execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_name = f"{role_name}-policy"

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    statements = [
        {
            "Effect": "Allow",
            "Action": ["states:StartExecution", "states:RedriveExecution"],
            "Resource": f"arn:aws:states:{ctx.region}:{account_id}:stateMachine:*",
        },
        {
            "Effect": "Allow",
            "Action": ["states:DescribeExecution", "states:StopExecution",
                       "states:RedriveExecution"],
            "Resource": f"arn:aws:states:{ctx.region}:{account_id}:execution:*:*",
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": f"arn:aws:s3:::{bucket}/*",
        },
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": f"arn:aws:s3:::{bucket}",
        },
        *extra,
    ]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation has no condition to poll; the bounded retries in _create_state_machine and
    # _run_to_terminal absorb it.
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD",
                          name_prefix="sim2real-behav-sm-"):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
    "States.Permissions",
    "AccessDenied",
)


def _run_to_terminal(ctx, sm_arn, input_payload, bucket, *, timeout_s=240.0, max_attempts=6):
    """Start an execution and poll to terminal, retrying a fresh one only on propagation races.

    The write prefix is cleared before each retry so a discarded attempt's writes are not counted.
    A wrong item split also retries: a propagation denial can abort the run with a generic cause.
    """
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        retry_worthy = any(m in blob for m in _PROPAGATION_MARKERS)
        if not retry_worthy and desc["status"] == "FAILED":
            map_run_arn = _one_map_run(ctx, exec_arn)
            counters = sfn.describe_map_run(mapRunArn=map_run_arn)["itemCounts"]
            retry_worthy = (counters["succeeded"], counters["failed"]) != (
                len(_OK_IDS), len(_FAIL_IDS)
            )
        if not retry_worthy:
            return desc
        _clear_prefix(ctx, bucket, _WRITE_PREFIX)
        time.sleep(5)
    return desc


def _clear_prefix(ctx, bucket, prefix):
    s3 = ctx.client("s3")
    keys = _list_keys(ctx, bucket, prefix)
    if keys:
        s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys]})


def _wait_terminal(ctx, exec_arn, *, timeout_s=240.0, interval_s=2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError:
        # An execution has no delete API; a terminal one may refuse the stop, any other refusal fails.
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
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


def _a_child_failure(ctx, map_run_arn):
    """One FAILED child's own error/cause, for diagnostics; itemCounts cannot say why it failed.

    ListExecutions takes a state machine ARN or a map run ARN, never both.
    """
    sfn = ctx.client("stepfunctions")
    resp = sfn.list_executions(mapRunArn=map_run_arn, statusFilter="FAILED", maxResults=1)
    if not resp["executions"]:
        return None
    child = sfn.describe_execution(executionArn=resp["executions"][0]["executionArn"])
    return {"error": child.get("error"), "cause": child.get("cause")}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
