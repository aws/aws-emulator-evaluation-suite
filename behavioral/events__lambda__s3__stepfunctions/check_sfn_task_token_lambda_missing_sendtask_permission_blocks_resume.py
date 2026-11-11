"""sfn-task-token-lambda-missing-sendtask-permission-blocks-resume."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-task-token-lambda-missing-sendtask-permission-blocks-resume"
GROUP = "task-token-callback"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A waitForTaskToken Lambda whose role lacks states:SendTaskSuccess gets AccessDeniedException and
    the execution stays RUNNING; after granting that role the permission, the identical call succeeds
    and the execution SUCCEEDS with the callback output."""
    bucket = _create_bucket(ctx)

    lambda_role_name, lambda_role_arn = _create_role(
        ctx,
        "sfn-behav-lam-role-",
        "lambda.amazonaws.com",
        {
            "s3-only": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"}
                ],
            }
        },
    )
    fn = _create_lambda(
        ctx,
        "sfn-behav-fn-",
        lambda_role_arn,
        (
            "import json\n"
            "import boto3\n"
            "from botocore.exceptions import ClientError\n\n"
            "def handler(event, context):\n"
            "    sfn = boto3.client('stepfunctions')\n"
            "    s3 = boto3.client('s3')\n"
            "    result = {'token': event['Token']}\n"
            "    try:\n"
            "        sfn.send_task_success(taskToken=event['Token'], output=json.dumps({'result': 'resumed-after-grant'}))\n"
            "        result['attempt'] = 'succeeded'\n"
            "    except ClientError as e:\n"
            "        result['attempt'] = 'denied'\n"
            "        result['error_code'] = e.response['Error']['Code']\n"
            "        result['error_message'] = e.response['Error']['Message']\n"
            "    s3.put_object(Bucket=event['Bucket'], Key=event['Key'], Body=json.dumps(result).encode())\n"
            "    return {'ok': True}\n"
        ),
    )
    _, sfn_role_arn = _create_role(
        ctx,
        "sfn-behav-sfn-role-",
        "states.amazonaws.com",
        {
            "invoke-lambda": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn["arn"]}
                ],
            }
        },
    )
    definition = {
        "StartAt": "WaitForCallback",
        "States": {
            "WaitForCallback": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
                "Parameters": {
                    "FunctionName": fn["arn"],
                    "Payload": {
                        "Token.$": "$$.Task.Token",
                        "Bucket": bucket,
                        "Key": "evidence.json",
                    },
                },
                # A just-created execution role may not be assumable yet (IAM eventual consistency),
                # which surfaces as States.TaskFailed on the first attempt.
                "Retry": [
                    {
                        "ErrorEquals": ["States.TaskFailed"],
                        "IntervalSeconds": 2,
                        "MaxAttempts": 4,
                        "BackoffRate": 2.0,
                    }
                ],
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, "sfn-behav-sm-", sfn_role_arn, definition)

    sfn = ctx.client("stepfunctions")
    s3 = ctx.client("s3")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({}))["executionArn"]

    evidence = _poll_for_object(s3, bucket, "evidence.json", timeout_s=60.0)
    assert evidence["attempt"] == "denied", evidence
    assert evidence["error_code"] == "AccessDeniedException", evidence
    account = sm_arn.split(":")[4]
    expected_message = (
        f"User: arn:aws:sts::{account}:assumed-role/{lambda_role_name}/{fn['name']} "
        f"is not authorized to perform: states:SendTaskSuccess on resource: {sm_arn} "
        "because no identity-based policy allows the states:SendTaskSuccess action"
    )
    assert evidence.get("error_message") == expected_message, evidence
    token = evidence["token"]

    # Effect absent: the callback never landed, so the execution is still RUNNING.
    status = sfn.describe_execution(executionArn=exec_arn)["status"]
    assert status == "RUNNING", f"execution should still be waiting, got {status}"

    # Positive control: grant the same role the permission and retry the identical call with the
    # same token until IAM's eventual consistency catches up.
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=lambda_role_name,
        PolicyName="send-task-success",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "states:SendTaskSuccess", "Resource": "*"}],
            }
        ),
    )

    restored = _retry_identical_call(ctx, fn["name"], s3, bucket, token, timeout_s=45.0, interval_s=3.0)
    assert restored["attempt"] == "succeeded", (
        f"the identical SendTaskSuccess call must succeed once the missing permission is "
        f"granted to the same role; got {restored}"
    )

    final = _poll_execution(sfn, exec_arn, timeout_s=60.0)
    assert final["status"] == "SUCCEEDED", final
    assert json.loads(final["output"]) == {"result": "resumed-after-grant"}, final


def _trust_policy(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
    }


def _create_role(ctx, name_prefix: str, trust_service: str, inline_policies: dict[str, dict]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_trust_policy(trust_service))
    )["Role"]["Arn"]

    def _cleanup() -> None:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for pname, doc in inline_policies.items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_name, role_arn


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda(ctx, name_prefix: str, role_arn: str, code: str, timeout: int = 30) -> dict[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(name_prefix)
    zip_bytes = _lambda_zip(code)
    fn_arn = None
    last_err = None
    for _ in range(15):
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
            )
            fn_arn = resp["FunctionArn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidParameterValueException", "AccessDeniedException"):
                last_err = e
                time.sleep(2.0)
                continue
            raise
    if fn_arn is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return {"name": fn_name, "arn": fn_arn}


def _create_state_machine(ctx, name_prefix: str, role_arn: str, definition: dict) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    sm_arn = None
    last_err = None
    for _ in range(15):
        try:
            sm_arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
            )["stateMachineArn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(2.0)
                continue
            raise
    if sm_arn is None:
        raise last_err
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
    return sm_arn


def _poll_execution(sfn, execution_arn: str, timeout_s: float = 90.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    resp = None
    while time.monotonic() < deadline:
        resp = sfn.describe_execution(executionArn=execution_arn)
        if resp["status"] != "RUNNING":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"execution stuck RUNNING after {timeout_s}s: {resp}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _poll_for_object(s3, bucket: str, key: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            return json.loads(body)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("NoSuchKey", "404"):
                raise
        time.sleep(interval_s)
    raise AssertionError(f"object {key!r} never appeared in {bucket!r} within {timeout_s}s")


def _invoke_lambda(ctx, fn_name: str, payload: dict) -> None:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=fn_name, Payload=json.dumps(payload).encode(), InvocationType="RequestResponse"
    )
    if resp.get("FunctionError"):
        body = resp["Payload"].read()
        raise AssertionError(f"lambda invocation raised: {body!r}")


def _retry_identical_call(
    ctx, fn_name: str, s3, bucket: str, token: str, timeout_s: float = 45.0, interval_s: float = 3.0
) -> dict:
    key = "evidence-restored.json"
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        _invoke_lambda(ctx, fn_name, {"Token": token, "Bucket": bucket, "Key": key})
        last = _poll_for_object(s3, bucket, key, timeout_s=10.0)
        if last["attempt"] == "succeeded":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"identical call never succeeded after granting permission within {timeout_s}s: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
