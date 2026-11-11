"""xsvc-sfn-1-athena-sync-missing-table-query-fails-as-task-failed."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-1-athena-sync-missing-table-query-fails-as-task-failed"
GROUP = 'sync_integration'
SERVICES = ['athena', 's3', 'stepfunctions']

_MANAGED_TAG_KEY = "sim2real:managed"
_TAG_PREFIX = "sim2real-xsvc"


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c3",
)
def run(ctx) -> None:
    """A query Athena accepts but fails at run time (missing table) turns the
    `athena:startQueryExecution.sync` task into exactly `States.TaskFailed` with Athena's
    TABLE_NOT_FOUND cause; a valid query through the same state machine succeeds first."""
    athena = ctx.client("athena")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    workgroup = _create_workgroup(ctx, bucket)
    role_arn = _create_sfn_role(ctx, bucket, account_id, workgroup)
    sm_arn = _create_state_machine(ctx, workgroup, role_arn)

    # Positive control through the same state machine, role and workgroup.
    marker = ctx.unique_name("sim2real-marker-")
    good = _run_to_terminal(ctx, sm_arn, f"SELECT '{marker}' AS marker")
    assert good["status"] == "SUCCEEDED", (
        f'the positive control was {good["status"]!r}: {good.get("error")!r} '
        f'{good.get("cause")!r}'
    )
    good_qid = json.loads(good["output"])["QueryExecution"]["QueryExecutionId"]
    good_rows = _query_rows(ctx, good_qid)
    assert good_rows == [["marker"], [marker]], (
        f"positive-control GetQueryResults returned {good_rows!r}"
    )

    # The one broken thing: the query names a table that does not exist.
    table = ctx.unique_name("sim2real_no_such_table_").replace("-", "_")
    bad = _run_to_terminal(ctx, sm_arn, f"SELECT * FROM {table}")
    assert bad["status"] == "FAILED", (
        f'a query over a missing table ended {bad["status"]!r}, expected FAILED'
    )
    assert bad.get("error") == "States.TaskFailed", (
        f'the execution failed with error {bad.get("error")!r}, expected States.TaskFailed'
    )
    cause = json.loads(bad["cause"])
    status = cause["QueryExecution"]["Status"]
    assert status["State"] == "FAILED", f"the Cause carries query status {status!r}"
    message = status["AthenaError"]["ErrorMessage"]
    assert re.match(r"TABLE_NOT_FOUND\b", message) and table in message, (
        f"the Cause's Athena error was {message!r}; expected TABLE_NOT_FOUND naming {table!r}"
    )

    history = _history(ctx, bad["executionArn"])
    types = [e["type"] for e in history]
    assert "TaskSucceeded" not in types and types.count("TaskFailed") == 1, (
        f"the failed execution's history was {types!r}"
    )
    failed = next(e for e in history if e["type"] == "TaskFailed")["taskFailedEventDetails"]
    assert failed["error"] == "States.TaskFailed", (
        f"the TaskFailed event carries error {failed['error']!r}"
    )

    # Independent read of Athena's own record of the query the task submitted.
    submitted = next(e for e in history if e["type"] == "TaskSubmitted")
    qid = json.loads(submitted["taskSubmittedEventDetails"]["output"])["QueryExecutionId"]
    assert cause["QueryExecution"]["QueryExecutionId"] == qid, (
        f"the Cause names query {cause['QueryExecution'].get('QueryExecutionId')!r}, the task "
        f"submitted {qid!r}"
    )
    qe = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    assert qe["Status"]["State"] == "FAILED", f"Athena reports query {qid} as {qe['Status']!r}"
    assert qe["Status"]["AthenaError"]["ErrorMessage"] == message, (
        f"Athena's own error {qe['Status']['AthenaError']!r} differs from the Cause's {message!r}"
    )
    assert qe["Status"]["CompletionDateTime"] <= bad["stopDate"], (
        f"the execution failed at {bad['stopDate'].isoformat()}, before Athena failed the query "
        f"at {qe['Status']['CompletionDateTime'].isoformat()}"
    )


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
    # IAM propagation is absorbed by the AccessDeniedException retry in _create_state_machine
    # and the propagation retry in _run_to_terminal.
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
    deadline = time.monotonic() + 90.0
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
    """Start an execution and poll to terminal; while a failure's cause names the fresh role's
    assumption or its first StartQueryExecution (IAM propagation), start a fresh execution
    every 2 s until a propagation deadline."""
    deadline = time.monotonic() + propagation_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        desc = _wait_terminal(ctx, _start(ctx, sm_arn, query), timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc
        if time.monotonic() >= deadline:
            return desc
        time.sleep(2)


def _wait_terminal(ctx, exec_arn, *, timeout_s=200.0, interval_s=2.0):
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
