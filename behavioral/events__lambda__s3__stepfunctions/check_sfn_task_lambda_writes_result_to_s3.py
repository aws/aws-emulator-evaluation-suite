"""sfn-task-lambda-writes-result-to-s3."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sfn-task-lambda-writes-result-to-s3"
GROUP = "sdk-call"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda task invoked by Step Functions writes its result to S3 via boto3;
    the object is then observable via GetObject with the expected content."""
    bucket = _create_bucket(ctx)

    lambda_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policies={
            "s3-write": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    }
                ],
            }
        },
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        ],
    )

    code = (
        "import boto3, json\n"
        "s3 = boto3.client('s3')\n\n"
        "def handler(event, context):\n"
        "    bucket = event['bucket']\n"
        "    key = event['key']\n"
        "    body = json.dumps({'echo': event.get('payload'), 'fn': 'writer'})\n"
        "    s3.put_object(Bucket=bucket, Key=key, Body=body.encode('utf-8'), ContentType='application/json')\n"
        "    return {'written': True, 'bucket': bucket, 'key': key}\n"
    )
    fn_arn = _create_function(ctx, lambda_role_arn, code, "index.handler")

    sfn_role_arn = _create_role(
        ctx,
        "states.amazonaws.com",
        inline_policies={
            "invoke-lambda": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}
                ],
            }
        },
    )

    definition = {
        "Comment": "sfn task lambda writes to s3",
        "StartAt": "WriteToS3",
        "States": {
            "WriteToS3": {
                "Type": "Task",
                "Resource": fn_arn,
                "End": True,
                # tolerate transient AccessDenied while the freshly-attached IAM
                # policies (SFN->Lambda invoke, Lambda->S3 put) are still propagating
                "Retry": [
                    {
                        "ErrorEquals": ["States.ALL"],
                        "IntervalSeconds": 5,
                        "MaxAttempts": 6,
                        "BackoffRate": 1.5,
                    }
                ],
            }
        },
    }
    sm_arn = _create_state_machine(ctx, sfn_role_arn, definition)

    key = ctx.unique_name("sim2real-obj-") + ".json"
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        input=json.dumps({"bucket": bucket, "key": key, "payload": "hello-check1"}),
    )["executionArn"]

    resp = _wait_execution(ctx, exec_arn, timeout_s=180)
    assert resp["status"] == "SUCCEEDED", f"execution ended in {resp['status']}: {resp.get('output')}"

    s3 = ctx.client("s3")
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    obj = json.loads(body)
    assert obj["echo"] == "hello-check1", f"expected echo='hello-check1', got {obj.get('echo')!r}"
    assert obj["fn"] == "writer", f"expected fn='writer', got {obj.get('fn')!r}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_role(
    ctx,
    service_principal: str,
    inline_policies: dict[str, Any] | None = None,
    managed_policy_arns: list[str] | None = None,
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function(ctx, role_arn: str, code: str, handler: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    buf.seek(0)
    zip_bytes = buf.read()
    last_err = None
    resp = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise last_err
    arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return arn


def _create_state_machine(ctx, role_arn: str, definition: dict[str, Any]) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    last_err = None
    resp = None
    for _ in range(10):
        try:
            resp = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
            )
            break
        except sfn.exceptions.AccessDeniedException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise last_err
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _wait_execution(ctx, exec_arn: str, timeout_s: float = 90.0) -> dict[str, Any]:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.describe_execution(executionArn=exec_arn)
        if resp["status"] != "RUNNING":
            return resp
        time.sleep(2)
    raise AssertionError("execution did not reach a terminal state in time")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
