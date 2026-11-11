"""lambda-sendtaskfailure-error-cause-length-limits."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sendtaskfailure-error-cause-length-limits"
GROUP = "task-token-callback"
SERVICES = ["lambda", "stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda calling SendTaskFailure with an over-the-limit error or cause is rejected and the
    waiting task is left live; the identical call at exactly the max length succeeds and the
    execution's error/cause round-trip the full, unterminated string."""
    max_error = "E" * 256
    max_cause = "C" * 32768
    over_error = "E" * 257
    over_cause = "C" * 32769

    lambda_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": ["states:SendTaskFailure", "states:SendTaskSuccess"], "Resource": "*"}],
    )
    sfn_role_arn = _create_role(
        ctx, "states.amazonaws.com", [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}]
    )

    code = (
        "import json\n"
        "import boto3\n"
        "from botocore.exceptions import ClientError\n\n"
        "def handler(event, context):\n"
        "    sfn = boto3.client('stepfunctions')\n"
        "    token = event['Token']\n"
        "    results = []\n"
        "    for error, cause in event['Attempts']:\n"
        "        try:\n"
        "            sfn.send_task_failure(taskToken=token, error=error, cause=cause)\n"
        "            results.append({'outcome': 'succeeded'})\n"
        "        except ClientError as e:\n"
        "            results.append({\n"
        "                'outcome': 'rejected',\n"
        "                'code': e.response['Error']['Code'],\n"
        "                'message': e.response['Error']['Message'],\n"
        "            })\n"
        "    if event['FinalError'] is None:\n"
        "        sfn.send_task_success(taskToken=token, output=json.dumps({'results': results}))\n"
        "    else:\n"
        "        sfn.send_task_failure(taskToken=token, error=event['FinalError'], cause=event['FinalCause'])\n"
        "    return {'ok': True}\n"
    )
    fn_arn = _create_lambda_function(ctx, code, lambda_role_arn)

    definition = {
        "StartAt": "WaitForToken",
        "States": {
            "WaitForToken": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
                "Parameters": {
                    "FunctionName": fn_arn,
                    "Payload": {
                        "Token.$": "$$.Task.Token",
                        "Attempts.$": "$.Attempts",
                        "FinalError.$": "$.FinalError",
                        "FinalCause.$": "$.FinalCause",
                    },
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, sfn_role_arn)

    # Rejected attempts: both lengths over the limit, surfaced through the task's own output
    # via the same SendTaskSuccess callback every other check in this suite uses.
    desc_rejected = _run_past_propagation(
        ctx,
        sm_arn,
        {"Attempts": [[over_error, "short cause"], ["short error", over_cause]], "FinalError": None, "FinalCause": None},
    )
    assert desc_rejected["status"] == "SUCCEEDED", (
        f"the task must still succeed via SendTaskSuccess after both oversized attempts were "
        f"rejected, not consumed, got {desc_rejected['status']}: {desc_rejected.get('error')}"
    )
    results = json.loads(desc_rejected["output"])["results"]
    assert len(results) == 2, results
    for attempt, field in zip(results, ("error", "cause")):
        assert attempt["outcome"] == "rejected", (
            f"an over-the-limit {field} must be rejected before it reaches the task token, got {attempt}"
        )
        assert attempt["code"] == "ValidationException", attempt
        limit = 256 if field == "error" else 32768
        expected = (
            f"1 validation error detected: Value at '{field}' failed to satisfy constraint: "
            f"Member must have length less than or equal to {limit}"
        )
        assert attempt["message"] == expected, attempt

    # Positive control: the identical shape, exactly at the max length, succeeds in reaching the
    # token, and the execution's recorded error/cause carry the full string, not a truncated one.
    desc_at_limit = _run_past_propagation(
        ctx, sm_arn, {"Attempts": [], "FinalError": max_error, "FinalCause": max_cause}
    )
    assert desc_at_limit["status"] == "FAILED", desc_at_limit
    assert desc_at_limit.get("error") == max_error, (
        f"error did not round-trip at the max length: len={len(desc_at_limit.get('error', ''))}"
    )
    assert desc_at_limit.get("cause") == max_cause, (
        f"cause did not round-trip at the max length: len={len(desc_at_limit.get('cause', ''))}"
    )


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx, principal, extra_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    statements = [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}
    ] + extra_statements
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements})
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_lambda_function(ctx, code, role_arn, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
    resp = None
    last_err = None
    for _ in range(12):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip_bytes(code)},
                Timeout=timeout,
                MemorySize=128,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidParameterValueException", "AccessDeniedException"):
                last_err = e
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    arn = None
    last_err = None
    for _ in range(12):
        try:
            resp = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real:managed", "value": "true"}],
            )
            arn = resp["stateMachineArn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(5)
                continue
            raise
    if arn is None:
        raise last_err
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
    return arn


def _poll_execution(sfn, exec_arn, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    resp = None
    while time.monotonic() < deadline:
        resp = sfn.describe_execution(executionArn=exec_arn)
        if resp["status"] != "RUNNING":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"execution stuck RUNNING after {timeout_s}s: {resp}")


# A fresh execution role whose trust or invoke grant has not propagated fails the invoke itself.
_PROPAGATION_NEEDLES = ("not authorized", "AccessDenied", "UnrecognizedClientException")


def _run_past_propagation(ctx, sm_arn, payload, timeout_s=180.0, interval_s=3.0):
    """Start executions until one ends other than in an IAM propagation failure of the invoke,
    and return its description; raises when propagation has not settled by the deadline."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
        last = _poll_execution(sfn, exec_arn, timeout_s=90.0)
        cause = last.get("cause") or ""
        propagating = last.get("error") == "Lambda.AWSLambdaException" or any(n in cause for n in _PROPAGATION_NEEDLES)
        if last["status"] != "FAILED" or not propagating:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"executions still failed on IAM propagation after {timeout_s}s: {last}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group still present after {budget_s}s of deletes; {absent} clean reads")
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
