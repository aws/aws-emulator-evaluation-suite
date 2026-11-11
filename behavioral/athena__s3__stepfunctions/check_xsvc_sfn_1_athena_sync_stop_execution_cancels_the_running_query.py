"""xsvc-sfn-1-athena-sync-stop-execution-cancels-the-running-query."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-1-athena-sync-stop-execution-cancels-the-running-query"
GROUP = 'sync_integration'
SERVICES = ['athena', 's3', 'stepfunctions']

_MANAGED_TAG_KEY = "sim2real:managed"
_TAG_PREFIX = "sim2real-xsvc"

# A query over no table that runs for many minutes: a 10^12-row cross join of generated
# sequences, so it scans zero bytes and stays RUNNING long enough to be stopped mid-flight.
_LONG_QUERY = (
    "SELECT count(*) FROM UNNEST(sequence(1, 10000)) a(x) "
    "CROSS JOIN UNNEST(sequence(1, 10000)) b(y) "
    "CROSS JOIN UNNEST(sequence(1, 10000)) c(z)"
)


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c3",
)
def run(ctx) -> None:
    """Stopping a Step Functions execution parked inside an `athena:startQueryExecution.sync` wait
    cancels the Athena query itself: read from Athena, the query ends CANCELLED."""
    athena = ctx.client("athena")
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    workgroup = _create_workgroup(ctx, bucket)
    role_arn = _create_sfn_role(ctx, bucket, account_id, workgroup)
    sm_arn = _create_state_machine(ctx, workgroup, role_arn)

    exec_arn, qid = _start_until_submitted(ctx, sm_arn, _LONG_QUERY)
    ctx.on_cleanup(lambda: _best_effort_cancel_query(ctx, qid))

    # Parked: the execution is RUNNING and Athena itself reports the query RUNNING.
    state = _wait_query_state(ctx, qid, {"RUNNING"}, timeout_s=90.0)
    assert state == "RUNNING", f"query {qid} never reached RUNNING, last state {state!r}"
    before = sfn.describe_execution(executionArn=exec_arn)
    assert before["status"] == "RUNNING", (
        f"the execution was {before['status']!r} while its query was still RUNNING"
    )

    sfn.stop_execution(executionArn=exec_arn, error="sim2real.Stop", cause="stop while parked")

    final = _wait_query_state(ctx, qid, {"SUCCEEDED", "FAILED", "CANCELLED"}, timeout_s=120.0)
    assert final == "CANCELLED", (
        f"after StopExecution the Athena query ended {final!r}, expected CANCELLED: stopping "
        f"a .sync execution must cancel the downstream query"
    )
    qe = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    assert "AthenaError" not in qe["Status"], (
        f"a cancelled query must carry no Athena error, got {qe['Status']!r}"
    )

    exe = sfn.describe_execution(executionArn=exec_arn)
    assert exe["status"] == "ABORTED", f"the stopped execution is {exe['status']!r}"
    assert (exe.get("error"), exe.get("cause")) == ("sim2real.Stop", "stop while parked"), (
        f"the aborted execution carries {exe.get('error')!r} / {exe.get('cause')!r}"
    )
    types = [e["type"] for e in _history(ctx, exec_arn)]
    assert types[-1] == "ExecutionAborted", f"the history ends with {types[-1]!r}: {types!r}"
    assert "TaskSucceeded" not in types and "TaskFailed" not in types, (
        f"a task stopped mid-wait must neither succeed nor fail: {types!r}"
    )


def _deadline(ctx, seconds):
    """A monotonic deadline `seconds` ahead, capped by the time the runner leaves this check."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


def _start_until_submitted(ctx, sm_arn, query, *, propagation_s=120.0, timeout_s=60.0):
    """Start, and return once the task has submitted its query (TaskSubmitted). A failure before
    submission races IAM propagation on the fresh role, so fresh executions are started until a
    deadline; one that keeps failing fails the check with its cause quoted."""
    sfn = ctx.client("stepfunctions")
    retry_until = _deadline(ctx, propagation_s)
    last = None
    while True:
        exec_arn = _start(ctx, sm_arn, query)
        deadline = _deadline(ctx, timeout_s)
        while time.monotonic() < deadline:
            for e in _history(ctx, exec_arn):
                if e["type"] == "TaskSubmitted":
                    out = json.loads(e["taskSubmittedEventDetails"]["output"])
                    return exec_arn, out["QueryExecutionId"]
            last = sfn.describe_execution(executionArn=exec_arn)
            if last["status"] != "RUNNING":
                break
            time.sleep(2)
        if last is None or last["status"] != "FAILED":
            raise AssertionError(f"the task never submitted its query: {last!r}")
        if time.monotonic() >= retry_until:
            break
        time.sleep(2)
    raise AssertionError(
        f"StartQueryExecution kept failing before submission: {last.get('error')!r} "
        f"{last.get('cause')!r}"
    )


def _wait_query_state(ctx, qid, wanted, *, timeout_s, interval_s=1.0):
    athena = ctx.client("athena")
    deadline = _deadline(ctx, timeout_s)
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in wanted:
            return state
        time.sleep(interval_s)
    return state


def _best_effort_cancel_query(ctx, qid):
    # StopQueryExecution on an already-terminal query is a documented no-op, not an error: nothing
    # here is expected to raise, so a real failure propagates instead of being swallowed.
    ctx.client("athena").stop_query_execution(QueryExecutionId=qid)


def _resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _TAG_PREFIX}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _tags_lower():
    return [{"key": k, "value": v} for k, v in _resource_tags().items()]


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-xsvc-athsfn-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv()})
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _list_keys(ctx, bucket, prefix):
    s3 = ctx.client("s3")
    out = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.update(o["Key"] for o in page.get("Contents", []))
    return out


def _create_workgroup(ctx, bucket):
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-xsvc-wg-")
    athena.create_work_group(
        Name=name,
        Description="sim2real-xsvc sfn athena .sync workgroup",
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    return name


_ATHENA_ACTIONS = (
    "athena:StartQueryExecution",
    "athena:GetQueryExecution",
    "athena:StopQueryExecution",
    "athena:GetWorkGroup",
)


def _create_sfn_role(ctx, bucket, account_id, workgroup, *, athena_actions=_ATHENA_ACTIONS):
    """The execution role: drive the query in this one workgroup, write its results to S3."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-athrole-")
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
        Description="sim2real-xsvc sfn athena .sync execution role",
        Tags=_tags_kv(),
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
        {
            "Effect": "Allow",
            "Action": list(athena_actions),
            "Resource": f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{workgroup}",
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketLocation", "s3:GetObject", "s3:PutObject", "s3:ListBucket",
                "s3:ListMultipartUploadParts", "s3:AbortMultipartUpload",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        },
        {
            "Effect": "Allow",
            "Action": ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables"],
            "Resource": "*",
        },
    ]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=f"{role_name}-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll: the AccessDeniedException retry in
    # _create_state_machine and the fresh-execution retry in _start_until_submitted absorb it.
    return role_arn


def _create_state_machine(ctx, workgroup, role_arn):
    sfn = ctx.client("stepfunctions")
    definition = {
        "Comment": "sim2real-xsvc: one athena startQueryExecution.sync task",
        "StartAt": "Query",
        "States": {
            "Query": {
                "Type": "Task",
                "Resource": "arn:aws:states:::athena:startQueryExecution.sync",
                "Parameters": {"QueryString.$": "$.query", "WorkGroup": workgroup},
                "End": True,
            }
        },
    }
    name = ctx.unique_name("sim2real-xsvc-athsm-")
    deadline = _deadline(ctx, 90.0)
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=_tags_lower(),
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
    "UnrecognizedClientException",
    "athena:StartQueryExecution",
)


def _start(ctx, sm_arn, query):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-xsvc-exec-"),
        input=json.dumps({"query": query}),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


def _run_to_terminal(ctx, sm_arn, query, *, timeout_s=200.0, propagation_s=120.0):
    """Start an execution and poll to terminal, absorbing IAM propagation at first use only: a
    failure naming the role assumption or StartQueryExecution is retried as a fresh execution."""
    retry_until = _deadline(ctx, propagation_s)
    while True:
        desc = _wait_terminal(ctx, _start(ctx, sm_arn, query), timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc
        if time.monotonic() >= retry_until:
            return desc
        time.sleep(2)


def _wait_terminal(ctx, exec_arn, *, timeout_s=200.0, interval_s=2.0):
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
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 200}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return out


def _query_rows(ctx, qid):
    athena = ctx.client("athena")
    rows = []
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        for row in page["ResultSet"]["Rows"]:
            rows.append([d.get("VarCharValue") for d in row["Data"]])
    return rows


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
