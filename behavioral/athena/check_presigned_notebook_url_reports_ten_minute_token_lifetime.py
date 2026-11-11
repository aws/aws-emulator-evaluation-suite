"""presigned-notebook-url-reports-ten-minute-token-lifetime."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "presigned-notebook-url-reports-ten-minute-token-lifetime"
GROUP = "visibility-timeout-ttl"
SERVICES = ["athena"]

# The notebook auth token lasts 10 minutes; AuthTokenExpirationTime carries that lifetime in seconds.
_TOKEN_LIFETIME_S = 600


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreatePresignedNotebookUrl reports the 10-minute token lifetime in AuthTokenExpirationTime, the
    NotebookUrl carries its AuthToken and opens at once, and a re-issued URL for the same live
    session carries a new token with the same lifetime and also opens.

    Reference: https://docs.aws.amazon.com/athena/latest/APIReference/API_CreatePresignedNotebookUrl.html
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket = _create_bucket(ctx)
    wg_name = ctx.unique_name("sim2real-athena-spark-wg-")
    wg_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg_name}"
    role_arn = _create_spark_execution_role(ctx, bucket, wg_arn, account_id)
    _create_spark_workgroup(ctx, wg_name, bucket, role_arn)

    athena = ctx.client("athena")
    notebook_id = athena.create_notebook(WorkGroup=wg_name, Name=ctx.unique_name("sim2real-nb-"))["NotebookId"]
    ctx.on_cleanup(lambda: athena.delete_notebook(NotebookId=notebook_id))

    session_id = _start_spark_session(ctx, wg_name, idle_timeout_minutes=30, notebook_id=notebook_id)

    first = athena.create_presigned_notebook_url(SessionId=session_id)
    assert first["AuthTokenExpirationTime"] == _TOKEN_LIFETIME_S, (
        f"AuthTokenExpirationTime must report the {_TOKEN_LIFETIME_S}s token lifetime, got "
        f"{first['AuthTokenExpirationTime']!r}"
    )
    assert first["AuthToken"] and first["AuthToken"] in urllib.parse.unquote(first["NotebookUrl"]), (
        "the NotebookUrl must include the AuthToken returned with it"
    )
    status_fresh = _http_status(ctx, first["NotebookUrl"])
    if status_fresh is None:
        raise AssertionError("outbound HTTPS to the Athena notebook endpoint is not reachable from this environment")
    assert status_fresh < 400, f"freshly issued notebook URL was rejected: HTTP {status_fresh}"

    second = athena.create_presigned_notebook_url(SessionId=session_id)
    assert second["AuthTokenExpirationTime"] == _TOKEN_LIFETIME_S, (
        f"a re-issued URL must report the same {_TOKEN_LIFETIME_S}s token lifetime, got "
        f"{second['AuthTokenExpirationTime']!r}"
    )
    assert second["AuthToken"] != first["AuthToken"], (
        "a re-issued notebook URL must carry a new AuthToken, not the one already issued"
    )
    status_second = _http_status(ctx, second["NotebookUrl"])
    assert status_second is not None and status_second < 400, (
        f"re-issued notebook URL for the still-live session was rejected: HTTP {status_second}"
    )


def _http_status(ctx, url: str):
    try:
        target_url, route_headers = ctx.endpoint_route(url)
        req = urllib.request.Request(target_url, method="GET", headers=route_headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except urllib.error.URLError:
        return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-spark-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_spark_execution_role(ctx, bucket_name: str, wg_arn: str, account_id: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust = {
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:ListBucket", "s3:DeleteObject", "s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
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
                "Condition": {"StringEquals": {"cloudwatch:namespace": "AmazonAthenaForApacheSpark"}},
            },
        ],
    }
    policy_name = "sim2real-athena-spark-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_spark_workgroup(ctx, wg_name: str, bucket_name: str, role_arn: str) -> None:
    athena = ctx.client("athena")
    config = {
        "ResultConfiguration": {"OutputLocation": f"s3://{bucket_name}/spark-output/"},
        "ExecutionRole": role_arn,
        "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
    }
    wg_tags = [{"Key": "sim2real", "Value": CHECK}]

    created = False
    last_error = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            athena.create_work_group(Name=wg_name, Configuration=config, Tags=wg_tags)
            created = True
            break
        except ClientError as exc:
            last_error = exc
            time.sleep(2)
    if not created:
        raise AssertionError(f"CreateWorkGroup never succeeded (IAM role propagation?): {last_error}")

    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))


def _start_spark_session(ctx, wg_name: str, idle_timeout_minutes: int, notebook_id: str) -> str:
    athena = ctx.client("athena")
    engine_cfg = {
        "CoordinatorDpuSize": 1,
        "DefaultExecutorDpuSize": 1,
        "MaxConcurrentDpus": 3,
        "AdditionalConfigs": {"NotebookId": notebook_id},
    }

    session_id = None
    last_error = None
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            session_id = athena.start_session(
                WorkGroup=wg_name,
                EngineConfiguration=engine_cfg,
                NotebookVersion="Athena notebook version 1",
                SessionIdleTimeoutInMinutes=idle_timeout_minutes,
            )["SessionId"]
            break
        except ClientError as exc:
            last_error = exc
            time.sleep(2)
    if session_id is None:
        raise AssertionError(f"StartSession never succeeded (IAM role propagation?): {last_error}")

    ctx.on_cleanup(lambda: _safe_terminate(ctx, session_id))

    state = _poll_until(
        lambda: athena.get_session_status(SessionId=session_id)["Status"]["State"],
        lambda s: s in ("IDLE", "FAILED", "DEGRADED"),
        timeout_s=600,
        interval_s=2,
    )
    if state != "IDLE":
        raise AssertionError(f"session did not reach IDLE, got {state}")
    return session_id


def _safe_terminate(ctx, session_id: str) -> None:
    athena = ctx.client("athena")
    try:
        athena.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
