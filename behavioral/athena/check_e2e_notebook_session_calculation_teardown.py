"""e2e-notebook-session-calculation-teardown."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-notebook-session-calculation-teardown"
GROUP = "e2e"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a Spark workgroup a session runs a calculation to a terminal status with its submitted
    code retrievable; once terminated, the session is TERMINATED and rejects further calculations
    with InvalidRequestException."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-athena-nb-")
    _create_bucket(ctx, s3, bucket)

    wg_name = ctx.unique_name("sim2real-athena-nb-wg-")
    wg_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg_name}"
    role_arn = _create_spark_execution_role(ctx, iam, wg_arn, bucket, account_id)

    _create_workgroup_with_retry(athena, wg_name, bucket, role_arn)
    ctx.on_cleanup(lambda: _safe_delete_workgroup(athena, wg_name))

    notebook_id = athena.create_notebook(WorkGroup=wg_name, Name=ctx.unique_name("nb-"))[
        "NotebookId"
    ]
    ctx.on_cleanup(lambda: _safe(lambda: athena.delete_notebook(NotebookId=notebook_id)))

    session_id = _start_session_with_retry(athena, wg_name, role_arn)
    ctx.on_cleanup(lambda: _safe(lambda: athena.terminate_session(SessionId=session_id)))

    def _idle():
        status = athena.get_session_status(SessionId=session_id)["Status"]
        state = status["State"]
        # CREATED is transient -- real AWS rejects StartCalculationExecution against it
        # ("needs to be IDLE to accept Calculations"), so only IDLE is ready.
        if state == "IDLE":
            return status
        if state in ("FAILED", "DEGRADED"):
            raise AssertionError(f"session entered {state}: {status}")
        return None

    _poll_until(_idle, timeout_s=300, interval_s=10)

    code_block = "spark.sql('SELECT 41 + 1').show()"
    calc_id = athena.start_calculation_execution(SessionId=session_id, CodeBlock=code_block)[
        "CalculationExecutionId"
    ]

    def _calc_terminal():
        status = athena.get_calculation_execution_status(CalculationExecutionId=calc_id)[
            "Status"
        ]
        state = status["State"]
        return status if state in ("COMPLETED", "FAILED", "CANCELED") else None

    calc_status = _poll_until(_calc_terminal, timeout_s=300, interval_s=10)
    assert calc_status["State"] == "COMPLETED", calc_status

    fetched_code = athena.get_calculation_execution_code(CalculationExecutionId=calc_id)[
        "CodeBlock"
    ]
    assert fetched_code == code_block

    calc_count_before_terminate = len(
        athena.list_calculation_executions(SessionId=session_id)["Calculations"]
    )
    assert calc_count_before_terminate == 1, calc_count_before_terminate

    athena.terminate_session(SessionId=session_id)

    def _terminated():
        status = athena.get_session_status(SessionId=session_id)["Status"]
        return status if status["State"] == "TERMINATED" else None

    term_status = _poll_until(_terminated, timeout_s=120, interval_s=5)
    assert term_status["State"] == "TERMINATED"

    rejected_code, rejected_msg = _error(
        lambda: athena.start_calculation_execution(
            SessionId=session_id, CodeBlock="spark.sql('SELECT 1')"
        )
    )
    assert rejected_code == "InvalidRequestException", rejected_code
    expected_msg = "Session is in the TERMINATED state; needs to be IDLE to accept Calculations."
    assert rejected_msg == expected_msg, f"expected {expected_msg!r}, got {rejected_msg!r}"

    calc_count_after_reject = len(
        athena.list_calculation_executions(SessionId=session_id)["Calculations"]
    )
    assert calc_count_after_reject == calc_count_before_terminate, (
        calc_count_after_reject,
        calc_count_before_terminate,
    )


def _create_bucket(ctx, s3, bucket: str) -> None:
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )

    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "notebook-session-calculation-teardown"}]},
    )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_spark_execution_role(ctx, iam, wg_arn: str, bucket: str, account_id: str) -> str:
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
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:ListBucket", "s3:DeleteObject", "s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
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
                    "athena:GetResourceDashboard",
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
                    f"arn:aws:logs:{ctx.region}:{account_id}:log-group:/aws-athena:*",
                    f"arn:aws:logs:{ctx.region}:{account_id}:log-group:/aws-athena*:log-stream:*",
                ],
            },
            {
                "Effect": "Allow",
                "Action": "logs:DescribeLogGroups",
                "Resource": f"arn:aws:logs:{ctx.region}:{account_id}:log-group:*",
            },
            {
                "Effect": "Allow",
                "Action": ["cloudwatch:PutMetricData"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"cloudwatch:namespace": "AmazonAthenaForApacheSpark"}
                },
            },
        ],
    }
    policy_name = ctx.unique_name("sim2real-athena-spark-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    return role_arn


def _create_workgroup_with_retry(
    athena, wg_name: str, bucket: str, role_arn: str, timeout_s: float = 60, interval_s: float = 5
) -> None:
    """CreateWorkGroup validates the ExecutionRole's trust policy eagerly, so a freshly
    created IAM role/policy pair can still be rejected as "Misconfigured service role"
    for a few seconds while IAM propagates -- retry instead of a fixed sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            athena.create_work_group(
                Name=wg_name,
                Configuration={
                    "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"},
                    "ExecutionRole": role_arn,
                    "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
                },
                Tags=[{"Key": "sim2real", "Value": "notebook-session-calculation-teardown"}],
            )
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRequestException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"CreateWorkGroup never succeeded (role propagation?): {last_err}")


def _start_session_with_retry(
    athena, wg_name: str, role_arn: str, timeout_s: float = 120, interval_s: float = 15
) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = athena.start_session(
                WorkGroup=wg_name,
                ExecutionRole=role_arn,
                EngineConfiguration={
                    "CoordinatorDpuSize": 1,
                    "MaxConcurrentDpus": 3,
                    "DefaultExecutorDpuSize": 1,
                },
            )
            return resp["SessionId"]
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"StartSession never succeeded (role propagation?): {last_err}")


def _safe_delete_workgroup(athena, name: str) -> None:
    _safe(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))


def _safe(fn) -> None:
    """Run a teardown call; only an already-gone resource is not a failure."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        msg = err.get("Message", "")
        gone = err.get("Code") in ("ResourceNotFoundException", "NoSuchEntity") or (
            err.get("Code") == "InvalidRequestException" and ("not found" in msg or "does not exist" in msg)
        )
        if not gone:
            raise


def _error(fn):
    """Call fn(); return its ClientError (code, message), or fail if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = probe()
        if result is not None:
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
