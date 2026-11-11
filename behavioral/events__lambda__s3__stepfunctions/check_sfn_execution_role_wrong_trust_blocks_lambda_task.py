"""sfn-execution-role-wrong-trust-blocks-lambda-task."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-execution-role-wrong-trust-blocks-lambda-task"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A state machine whose role trusts lambda.amazonaws.com but not states.amazonaws.com
    fails with a not-authorized-to-assume cause and never invokes the Lambda, while a correctly
    trusted twin succeeds."""
    bucket = _create_bucket(ctx)

    fn_role_arn = _create_role(
        ctx,
        "sfn-behav-fn-role-",
        "lambda.amazonaws.com",
        {
            "s3-put": {
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
        fn_role_arn,
        (
            "import boto3\n\n"
            "def handler(event, context):\n"
            "    s3 = boto3.client('s3')\n"
            "    s3.put_object(Bucket=event['Bucket'], Key=event['Key'], Body=b'invoked')\n"
            "    return {'invoked': True}\n"
        ),
    )

    definition = {
        "StartAt": "InvokeLambda",
        "States": {
            "InvokeLambda": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": fn["arn"], "Payload.$": "$"},
                # The execution role is freshly created; IAM's eventual consistency can
                # make the very first InvokeFunction call from a CORRECTLY-trusted role
                # bounce with States.TaskFailed ("... is not authorized to assume the
                # provided role") before the policy has propagated. Retry that specific
                # error so the positive control isn't flaky. The wrong-trust negative
                # below hits the SAME error/cause but for a permanent reason (the
                # principal is not states.amazonaws.com), so it keeps failing across
                # every retry and still ends FAILED well within the poll timeout.
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

    lambda_invoke_policy = {
        "invoke-lambda": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn["arn"]}
            ],
        }
    }

    # --- Negative: trust policy names the WRONG principal (lambda, not states) ---
    wrong_trust_role_arn = _create_role(
        ctx, "sfn-behav-wrong-role-", "lambda.amazonaws.com", lambda_invoke_policy
    )
    wrong_sm_arn = _create_state_machine(ctx, "sfn-behav-wrong-sm-", wrong_trust_role_arn, definition)

    sfn = ctx.client("stepfunctions")
    s3 = ctx.client("s3")
    wrong_key = "wrong-trust-marker"
    wrong_exec_arn = sfn.start_execution(
        stateMachineArn=wrong_sm_arn, input=json.dumps({"Bucket": bucket, "Key": wrong_key})
    )["executionArn"]

    wrong_final = _poll_execution(sfn, wrong_exec_arn, timeout_s=90.0)
    assert wrong_final["status"] == "FAILED", f"unexpected status: {wrong_final}"
    assert "not authorized to assume" in wrong_final.get("cause", ""), wrong_final
    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=wrong_key)) == "404", (
        "Lambda must never have been invoked when the execution role could not be assumed"
    )

    # --- Positive control: same Lambda, same Task type, correctly-trusted role ---
    correct_trust_role_arn = _create_role(
        ctx, "sfn-behav-correct-role-", "states.amazonaws.com", lambda_invoke_policy
    )
    correct_sm_arn = _create_state_machine(
        ctx, "sfn-behav-correct-sm-", correct_trust_role_arn, definition
    )
    correct_key = "correct-trust-marker"
    correct_exec_arn = sfn.start_execution(
        stateMachineArn=correct_sm_arn, input=json.dumps({"Bucket": bucket, "Key": correct_key})
    )["executionArn"]

    correct_final = _poll_execution(sfn, correct_exec_arn, timeout_s=90.0)
    assert correct_final["status"] == "SUCCEEDED", f"unexpected status: {correct_final}"
    marker = s3.get_object(Bucket=bucket, Key=correct_key)["Body"].read()
    assert marker == b"invoked", marker


def _mgmt_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:check": CHECK}


def _trust_policy(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
    }


def _create_role(ctx, name_prefix: str, trust_service: str, inline_policies: dict[str, dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy(trust_service)),
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        for pname in inline_policies:
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
    return role_arn


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
                Tags=_mgmt_tags(),
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
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": k, "value": v} for k, v in _mgmt_tags().items()],
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
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _mgmt_tags().items()]}
    )

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _error_code(fn) -> str:
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
