"""telemetry-resource-dashboard-reflects-query-activity."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "telemetry-resource-dashboard-reflects-query-activity"
GROUP = "telemetry"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceDashboard rejects a never-existing session ARN under a live Spark workgroup with
    InvalidRequestException, and returns an https dashboard URL once a real session is IDLE."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-athena-dash-")
    _create_bucket(ctx, s3, bucket)

    wg_name = ctx.unique_name("sim2real-athena-dash-wg-")
    wg_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg_name}"
    role_arn = _create_spark_execution_role(ctx, iam, wg_arn, bucket, account_id)

    spark_version = _find_spark_engine_version(athena)
    _create_work_group_with_retry(athena, wg_name, role_arn, spark_version)
    ctx.on_cleanup(lambda: _safe_delete_workgroup(athena, wg_name))

    # Athena answers InvalidRequestException, not ResourceNotFoundException, here. The id is
    # well-formed ("s-" plus lowercase alphanumerics) so the refusal is the lookup, not validation.
    bogus_session_arn = f"{wg_arn}/session/{ctx.unique_name('s-')}"
    err = _error(lambda: athena.get_resource_dashboard(ResourceARN=bogus_session_arn))
    expected = ("InvalidRequestException", "ResourceARN is not found")
    assert err == expected, (
        f"GetResourceDashboard on a never-existed session under a live workgroup "
        f"that never had a session: expected {expected}, got {err!r}"
    )

    session_id = _start_session_with_retry(athena, wg_name)
    ctx.on_cleanup(lambda: _safe(lambda: athena.terminate_session(SessionId=session_id)))

    def _idle():
        status = athena.get_session_status(SessionId=session_id)["Status"]
        state = status["State"]
        if state in ("IDLE", "CREATED"):
            return status
        if state in ("FAILED", "DEGRADED"):
            raise AssertionError(f"session entered {state}: {status}")
        return None

    _poll_until(_idle, timeout_s=300, interval_s=10)

    session_arn = f"{wg_arn}/session/{session_id}"
    dashboard = athena.get_resource_dashboard(ResourceARN=session_arn)
    assert dashboard["Url"].startswith("https://"), dashboard["Url"]


def _create_bucket(ctx, s3, bucket: str) -> None:
    region = ctx.region
    # S3 rejects an explicit LocationConstraint of "us-east-1"; it must be omitted there.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "telemetry-resource-dashboard-reflects-query-activity"}]},
    )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_spark_execution_role(ctx, iam, wg_arn: str, bucket: str, account_id: str) -> str:
    role_name = ctx.unique_name("sim2real-athena-dash-role-")
    # No SourceAccount/SourceArn condition: CreateWorkGroup assumes the role before the workgroup
    # exists, so a condition on the workgroup ARN fails with "Misconfigured service role".
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "athena.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "telemetry-resource-dashboard-reflects-query-activity"}],
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
    policy_name = ctx.unique_name("sim2real-athena-dash-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )

    return role_arn


def _find_spark_engine_version(athena) -> str:
    # Spark engine version strings vary by partition; read the advertised one.
    resp = athena.list_engine_versions()
    for ev in resp.get("EngineVersions", []):
        selected = ev.get("EngineVersion", ev).get("SelectedEngineVersion", "")
        if "Spark" in selected:
            return selected
    raise AssertionError("no Spark-capable engine version advertised by ListEngineVersions")


def _create_work_group_with_retry(
    athena,
    wg_name: str,
    role_arn: str,
    spark_version: str,
    timeout_s: float = 90,
    interval_s: float = 10,
) -> None:
    """Retry CreateWorkGroup, which assumes the execution role, until IAM propagation completes."""
    from botocore.exceptions import ClientError

    # No ResultConfiguration: Athena rejects it on a Spark-engine workgroup ("ResultConfiguration
    # is not supported for this engine configuration").
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            athena.create_work_group(
                Name=wg_name,
                Configuration={
                    "ExecutionRole": role_arn,
                    "EngineVersion": {"SelectedEngineVersion": spark_version},
                },
                Tags=[{"Key": "sim2real", "Value": "telemetry-resource-dashboard-reflects-query-activity"}],
            )
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRequestException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"CreateWorkGroup never succeeded (role propagation?): {last_err}")


def _start_session_with_retry(
    athena, wg_name: str, timeout_s: float = 120, interval_s: float = 15
) -> str:
    """Retry StartSession until the just-created execution role is assumable by Athena."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            # No ExecutionRole: the workgroup enforces its own. EngineConfiguration is empty
            # because Athena rejects DPU size fields for this Spark engine version.
            resp = athena.start_session(
                WorkGroup=wg_name,
                EngineConfiguration={},
            )
            return resp["SessionId"]
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"StartSession never succeeded (role propagation?): {last_err}")


def _safe_delete_workgroup(athena, name: str) -> None:
    try:
        athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "not found" in err.get("Message", "")):
            raise


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


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
