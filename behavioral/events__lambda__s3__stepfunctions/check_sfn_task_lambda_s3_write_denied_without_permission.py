"""sfn-task-lambda-s3-write-denied-without-permission."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sfn-task-lambda-s3-write-denied-without-permission"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """When the Lambda task's role lacks s3:PutObject, the write fails (caught and
    reported by the handler) and no object appears in the bucket; the same workflow
    invoking a Lambda whose role HAS the permission succeeds and the object appears."""
    bucket = _create_bucket(ctx)

    code = (
        "import boto3, json\n"
        "from botocore.exceptions import ClientError\n"
        "s3 = boto3.client('s3')\n\n"
        "def handler(event, context):\n"
        "    bucket = event['bucket']\n"
        "    key = event['key']\n"
        "    try:\n"
        "        s3.put_object(Bucket=bucket, Key=key, Body=json.dumps({'ok': True}).encode('utf-8'))\n"
        "        return {'success': True}\n"
        "    except ClientError as e:\n"
        "        return {'success': False, 'error': e.response['Error']['Code']}\n"
    )

    denied_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    denied_fn_arn = _create_function(ctx, denied_role_arn, code, "index.handler")

    allowed_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policies={
            "s3-write": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"}
                ],
            }
        },
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    allowed_fn_arn = _create_function(ctx, allowed_role_arn, code, "index.handler")

    sfn_role_arn = _create_role(
        ctx,
        "states.amazonaws.com",
        inline_policies={
            "invoke-lambda": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": [denied_fn_arn, allowed_fn_arn],
                    }
                ],
            }
        },
    )

    definition = {
        "StartAt": "Invoke",
        "States": {
            "Invoke": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName.$": "$.functionArn", "Payload.$": "$"},
                # The sfn role's invoke-lambda policy was attached moments ago; IAM's
                # eventual consistency can bounce the first InvokeFunction call with a
                # task failure before the grant propagates. Retry that, bounded, rather
                # than sleeping before either execution starts.
                "Retry": [
                    {
                        "ErrorEquals": ["States.ALL"],
                        "IntervalSeconds": 3,
                        "MaxAttempts": 5,
                        "BackoffRate": 1.5,
                    }
                ],
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, sfn_role_arn, definition)

    s3 = ctx.client("s3")

    # --- negative: role without s3:PutObject ---
    denied_key = ctx.unique_name("sim2real-denied-") + ".json"
    denied_resp = _run_execution(
        ctx, sm_arn, {"functionArn": denied_fn_arn, "bucket": bucket, "key": denied_key}
    )
    assert denied_resp["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {denied_resp['status']}"
    denied_payload = json.loads(denied_resp["output"])["Payload"]
    assert denied_payload["success"] is False, f"expected success=False, got {denied_payload}"
    assert denied_payload["error"] == "AccessDenied", f"expected AccessDenied, got {denied_payload}"

    code_absence, message_absence = _error(lambda: s3.get_object(Bucket=bucket, Key=denied_key))
    assert code_absence == "NoSuchKey", f"expected NoSuchKey, got {code_absence!r}"
    assert message_absence == "The specified key does not exist.", (
        f"expected GetObject's NoSuchKey message 'The specified key does not exist.', got {message_absence!r}"
    )

    # --- positive control: same workflow, role WITH s3:PutObject. That role's inline
    # s3-write policy was attached moments ago too, but the ASL Retry above cannot see
    # this propagation delay: the Lambda invocation itself succeeds either way, and only
    # the put_object call inside the handler observes the stale permission set and
    # returns success=False. Retry the whole execution, bounded, until the grant is
    # visible or the deadline is spent.
    allowed_key = ctx.unique_name("sim2real-allowed-") + ".json"
    deadline = time.monotonic() + 60.0
    allowed_payload: dict[str, Any] = {}
    while True:
        allowed_resp = _run_execution(
            ctx, sm_arn, {"functionArn": allowed_fn_arn, "bucket": bucket, "key": allowed_key}
        )
        assert allowed_resp["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {allowed_resp['status']}"
        allowed_payload = json.loads(allowed_resp["output"])["Payload"]
        if allowed_payload["success"] is True or time.monotonic() >= deadline:
            break
        time.sleep(5)
    assert allowed_payload["success"] is True, f"expected success=True, got {allowed_payload}"

    body = s3.get_object(Bucket=bucket, Key=allowed_key)["Body"].read()
    assert json.loads(body)["ok"] is True, f"expected ok=True in written object, got {body!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
                Tags={"sim2real": CHECK},
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
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
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


def _run_execution(ctx, sm_arn: str, payload: dict[str, Any], timeout_s: float = 90.0) -> dict[str, Any]:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]
    return _wait_execution(ctx, exec_arn, timeout_s=timeout_s)


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
