"""notebook-sessions-list-scoped-to-notebook."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notebook-sessions-list-scoped-to-notebook"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNotebookSessions returns only the sessions started against the notebook it was
    called with -- a session started for notebook A shows up under A's session list, but
    not under a sibling notebook B's list in the same workgroup."""
    athena = ctx.client("athena")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    wg_name = ctx.unique_name("sim2real-athena-sparkwg-")
    wg_arn = f"arn:aws:athena:{region}:{account_id}:workgroup/{wg_name}"

    bucket = _create_results_bucket(ctx)
    role_arn = _create_spark_execution_role(ctx, account_id, region, wg_arn, bucket)
    _create_spark_workgroup(ctx, athena, wg_name, bucket, role_arn)

    notebook_a = athena.create_notebook(WorkGroup=wg_name, Name=ctx.unique_name("nb-a-"))["NotebookId"]
    ctx.on_cleanup(lambda: _swallow(lambda: athena.delete_notebook(NotebookId=notebook_a)))
    notebook_b = athena.create_notebook(WorkGroup=wg_name, Name=ctx.unique_name("nb-b-"))["NotebookId"]
    ctx.on_cleanup(lambda: _swallow(lambda: athena.delete_notebook(NotebookId=notebook_b)))

    session_id = _start_session_with_retry(
        athena,
        wg_name,
        role_arn,
        extra={
            "NotebookVersion": "Athena notebook version 1",
            "EngineConfiguration": {
                "CoordinatorDpuSize": 1,
                "DefaultExecutorDpuSize": 1,
                "MaxConcurrentDpus": 3,
                "AdditionalConfigs": {"NotebookId": notebook_a},
            },
        },
    )
    ctx.on_cleanup(lambda: _terminate_session_best_effort(athena, session_id))

    # The session belongs to notebook A: it must show up in A's active-session list.
    scoped_sessions = _poll_until(
        lambda: {
            s["SessionId"]
            for s in athena.list_notebook_sessions(NotebookId=notebook_a)["NotebookSessionsList"]
        },
        lambda ids: session_id in ids,
        timeout_s=60.0,
        interval_s=5.0,
        description=f"session {session_id} to appear under notebook {notebook_a}",
    )
    assert session_id in scoped_sessions, (
        f"session {session_id} never appeared under its own notebook {notebook_a}: {scoped_sessions!r}"
    )

    # It must NOT show up under the sibling notebook B in the same workgroup.
    other_sessions = {
        s["SessionId"]
        for s in athena.list_notebook_sessions(NotebookId=notebook_b)["NotebookSessionsList"]
    }
    assert session_id not in other_sessions, (
        f"session {session_id} started for notebook {notebook_a} leaked into notebook {notebook_b}'s list"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} (last value: {last!r})")


def _create_results_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-spark-res-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "notebook-sessions-list-scoped-to-notebook"}]},
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_spark_execution_role(ctx, account_id: str, region: str, wg_arn: str, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "athena.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": wg_arn},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "notebook-sessions-list-scoped-to-notebook"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:ListBucket", "s3:DeleteObject", "s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/*", f"arn:aws:s3:::{bucket}"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "athena:GetWorkGroup",
                    "athena:CreatePresignedNotebookUrl",
                    "athena:TerminateSession",
                    "athena:GetSession",
                    "athena:GetSessionStatus",
                    "athena:ListSessions",
                    "athena:StartCalculationExecution",
                    "athena:GetCalculationExecutionCode",
                    "athena:StopCalculationExecution",
                    "athena:ListCalculationExecutions",
                    "athena:GetCalculationExecution",
                    "athena:GetCalculationExecutionStatus",
                    "athena:ListExecutors",
                    "athena:ExportNotebook",
                    "athena:UpdateNotebook",
                ],
                "Resource": wg_arn,
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogStream",
                    "logs:DescribeLogStreams",
                    "logs:CreateLogGroup",
                    "logs:PutLogEvents",
                ],
                "Resource": [
                    f"arn:aws:logs:{region}:{account_id}:log-group:/aws-athena:*",
                    f"arn:aws:logs:{region}:{account_id}:log-group:/aws-athena*:log-stream:*",
                ],
            },
            {
                "Effect": "Allow",
                "Action": "logs:DescribeLogGroups",
                "Resource": f"arn:aws:logs:{region}:{account_id}:log-group:*",
            },
            {
                "Effect": "Allow",
                "Action": ["cloudwatch:PutMetricData"],
                "Resource": "*",
                "Condition": {"StringEquals": {"cloudwatch:namespace": "AmazonAthenaForApacheSpark"}},
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="spark-session-permissions",
        PolicyDocument=json.dumps(permissions_policy),
    )
    return role_arn


def _delete_role(iam, role_name: str) -> None:
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_spark_workgroup(ctx, athena, wg_name: str, bucket: str, role_arn: str) -> None:
    athena.create_work_group(
        Name=wg_name,
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"},
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ExecutionRole": role_arn,
        },
        Tags=[{"Key": "sim2real", "Value": "notebook-sessions-list-scoped-to-notebook"}],
    )
    ctx.on_cleanup(
        lambda: _swallow(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))
    )


def _swallow(fn) -> None:
    """Run a teardown call; only an already-gone resource is not a failure."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "not found" in err.get("Message", "")):
            raise


def _start_session_with_retry(athena, wg_name: str, role_arn: str, extra: dict | None = None) -> str:
    kwargs = dict(
        WorkGroup=wg_name,
        ExecutionRole=role_arn,
        EngineConfiguration={"CoordinatorDpuSize": 1, "DefaultExecutorDpuSize": 1, "MaxConcurrentDpus": 3},
        SessionIdleTimeoutInMinutes=15,
    )
    if extra:
        kwargs.update(extra)
    # IAM role trust/permissions can take a few seconds to propagate after creation, so
    # retry StartSession for a bounded window rather than failing on the first attempt.
    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return athena.start_session(**kwargs)["SessionId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(5.0)
    raise AssertionError(f"StartSession never succeeded (IAM role propagation?): {last_exc}")


def _terminate_session_best_effort(athena, session_id: str) -> None:
    _poll_until(
        lambda: athena.get_session_status(SessionId=session_id)["Status"]["State"],
        lambda s: s in ("CREATED", "IDLE", "BUSY", "TERMINATED", "FAILED", "DEGRADED"),
        timeout_s=300.0,
        interval_s=2.0,
        description=f"session {session_id} to leave CREATING before cleanup termination",
    )
    try:
        athena.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    # A notebook bound to a session that is still terminating cannot be deleted.
    _poll_until(
        lambda: athena.get_session_status(SessionId=session_id)["Status"]["State"],
        lambda s: s in ("TERMINATED", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
        description=f"session {session_id} to finish terminating",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
