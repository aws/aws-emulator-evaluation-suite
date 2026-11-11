"""glue-job-assumes-role-sends-sqs-message-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "glue-job-assumes-role-sends-sqs-message-positive"
GROUP = "permission-boundary"
SERVICES = ["glue", "sqs"]

_SCRIPT = (
    "import sys\n"
    "import boto3\n"
    "\n"
    "def _args():\n"
    "    out = {}\n"
    "    argv = sys.argv[1:]\n"
    "    i = 0\n"
    "    while i < len(argv):\n"
    "        if argv[i].startswith('--'):\n"
    "            out[argv[i][2:]] = argv[i + 1] if i + 1 < len(argv) else ''\n"
    "            i += 2\n"
    "        else:\n"
    "            i += 1\n"
    "    return out\n"
    "\n"
    "args = _args()\n"
    "sqs = boto3.client('sqs', region_name=args.get('REGION'))\n"
    "try:\n"
    "    sqs.send_message(QueueUrl=args['QUEUE_URL'], MessageBody=args['MESSAGE_BODY'])\n"
    "    print('SEND_OK')\n"
    "    sys.exit(0)\n"
    "except Exception as e:\n"
    "    print('SEND_FAILED:' + str(e))\n"
    "    sys.exit(1)\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job, running under a role that trusts glue.amazonaws.com and holds
    sqs:SendMessage, actually delivers a message to the target queue end-to-end."""
    ctx.client("sqs")
    queue_url, queue_arn = _create_queue(ctx)

    script_uri, bucket = _upload_script(ctx, _SCRIPT)
    bucket_arn = f"arn:aws:s3:::{bucket}/*"
    sqs_statement = [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]
    role_name, role_arn = _create_glue_role(ctx, bucket_arn, sqs_statement)
    job_name = _create_pythonshell_job(ctx, role_arn, script_uri)

    message_body = ctx.unique_name("sim2real-glue-payload-")
    arguments = {
        "--QUEUE_URL": queue_url,
        "--MESSAGE_BODY": message_body,
        "--REGION": ctx.region,
    }
    final = _run_job_until_role_propagates(ctx, job_name, arguments)
    assert final["JobRunState"] == "SUCCEEDED", f"unexpected terminal state: {final}"

    body = _poll_for_message_body(ctx, queue_url, timeout_s=90, interval_s=3)
    assert body == message_body, f"expected {message_body!r}, got {body!r}"


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-glue-target-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _upload_script(ctx, body: str) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-scripts-")
    # us-east-1 is the one region where S3 rejects an explicit LocationConstraint;
    # this is the CreateBucket API contract, not a hardcoded test-region assumption.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_object(Bucket=bucket, Key="script.py", Body=body.encode("utf-8"))
    return f"s3://{bucket}/script.py", bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_glue_role(ctx, script_bucket_arn: str, extra_statements: list[dict[str, Any]] | None = None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    statements = [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": script_bucket_arn},
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        },
    ]
    if extra_statements:
        statements.extend(extra_statements)
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-perms", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-perms"))
    return role_name, role_arn


def _create_pythonshell_job(ctx, role_arn: str, script_uri: str) -> str:
    glue = ctx.client("glue")
    job_name = ctx.unique_name("sim2real-glue-job-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={"Name": "pythonshell", "ScriptLocation": script_uri, "PythonVersion": "3.9"},
        MaxCapacity=0.0625,
        Timeout=5,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return job_name


def _start_job_run_with_retry(ctx, job_name: str, arguments: dict[str, str], timeout_s: float = 90, interval_s: float = 10) -> str:
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = glue.start_job_run(JobName=job_name, Arguments=arguments)
            return resp["JobRunId"]
        except Exception as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"start_job_run kept failing: {last_err}")


def _run_job_until_role_propagates(
    ctx, job_name: str, arguments: dict[str, str], retry_budget_s: float = 90, interval_s: float = 15
) -> dict[str, Any]:
    """A role trust/inline policy created moments ago is not necessarily visible yet to the
    Glue execution control plane; a run started too soon fails with a deterministic
    InvalidInputException ("should be given assume role permissions for Glue Service") rather
    than an API-level rejection, so `_start_job_run_with_retry` alone cannot catch it. Retry the
    whole run, bounded, only for that specific propagation signature."""
    deadline = time.monotonic() + retry_budget_s
    last: dict[str, Any] = {}
    while True:
        run_id = _start_job_run_with_retry(ctx, job_name, arguments)
        last = _wait_for_job_run(ctx, job_name, run_id, timeout_s=480, interval_s=15)
        if last["JobRunState"] == "SUCCEEDED":
            return last
        if "assume role permissions" not in last.get("ErrorMessage", "") or time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


def _wait_for_job_run(ctx, job_name: str, run_id: str, timeout_s: float = 480, interval_s: float = 15) -> dict[str, Any]:
    glue = ctx.client("glue")
    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = glue.get_job_run(JobName=job_name, RunId=run_id)
        last = resp["JobRun"]
        if last["JobRunState"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"job run did not reach terminal state in {timeout_s}s, last={last}")


def _poll_for_message_body(ctx, queue_url: str, timeout_s: float = 90, interval_s: float = 3) -> str | None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
        time.sleep(max(0.0, interval_s - 2))
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
