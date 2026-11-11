"""sfn-retry-with-backoff."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-retry-with-backoff"
GROUP = 'task_state'
SERVICES = ['stepfunctions']

def _create_state_machine_with_role(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
        type=sm_type,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


def _run_execution(ctx, sm_arn, *, input_data=None, max_attempts=8, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    input_str = None if input_data is None else json.dumps(input_data)
    desc = None
    for attempt in range(max_attempts):
        kwargs = {"stateMachineArn": sm_arn}
        if input_str is not None:
            kwargs["input"] = input_str
        exec_arn = sfn.start_execution(**kwargs)["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
        desc = _wait_execution_complete(ctx, exec_arn, timeout_s=timeout_s)
        if desc["status"] != "FAILED":
            return desc
        cause = (desc.get("cause") or "") + (desc.get("error") or "")
        if not any(m in cause for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(10 + attempt * 5)
    raise AssertionError(
        f"Step Functions role trust did not propagate after {max_attempts} attempts "
        f"(last cause: {desc.get('cause') if desc else 'n/a'})"
    )


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


def _get_history_events(ctx, exec_arn, *, reverse=False):
    sfn = ctx.client("stepfunctions")
    events = []
    kwargs = {"executionArn": exec_arn, "reverseOrder": reverse}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if "nextToken" not in resp:
            break
        kwargs["nextToken"] = resp["nextToken"]
    return events


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_sfn_role_for_lambda(ctx, lambda_arns):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Path="/sim2real/",
        Description="Behavioral SFN task-integration execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _del_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    resources = []
    for a in lambda_arns:
        resources.append(a)
        resources.append(a + ":*")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="invoke-lambda",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": resources,
            }],
        }),
    )
    # No sleep here: role-trust propagation into a running state machine is exactly what
    # _run_execution's bounded retry-on-AssumeRole-failure loop already waits out.
    return role_arn


def _create_lambda(ctx, handler_code, *, env=None, timeout=30, memory=128, runtime="python3.12"):
    import zipfile
    from io import BytesIO

    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-behav-lrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Path="/sim2real/",
        Description="Behavioral SFN task-integration Lambda execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _del_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            }],
        }),
    )
    # No sleep here: the create_function retry loop below already waits out role-trust
    # propagation, bounded by its own 40s deadline.

    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)

    fn_name = ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": fn_name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": {"sim2real": CHECK},
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    deadline = time.monotonic() + 40
    last_err = None
    arn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            arn = lam.create_function(**kwargs)["FunctionArn"]
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
            break
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or "InvalidParameterValue" in msg:
                last_err = exc
                time.sleep(3)
                continue
            raise
    if arn is None:
        raise last_err or RuntimeError(f"Failed to create Lambda {fn_name}")

    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name),
        lambda r: r.get("State") == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"Lambda {fn_name} active",
    )
    return {"name": fn_name, "arn": arn}

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Task whose Lambda always throws is retried by its Retry block (MaxAttempts 2, with backoff), then
    caught by States.ALL into a recovery Pass: the execution SUCCEEDS with output
    "recovered-after-retries" and the history shows at least three scheduled attempts."""
    handler_code = (
        "def lambda_handler(event, context):\n"
        "    raise Exception('intentional transient failure')\n"
    )
    fn = _create_lambda(ctx, handler_code)
    role_arn = _create_sfn_role_for_lambda(ctx, [fn["arn"]])
    definition = {
        "StartAt": "InvokeWithRetry",
        "States": {
            "InvokeWithRetry": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": fn["arn"], "Payload.$": "$"},
                "Retry": [
                    {
                        "ErrorEquals": ["States.TaskFailed"],
                        "IntervalSeconds": 1,
                        "MaxAttempts": 2,
                        "BackoffRate": 2.0,
                    }
                ],
                "Catch": [
                    {
                        "ErrorEquals": ["States.ALL"],
                        "ResultPath": "$.error",
                        "Next": "Recovered",
                    }
                ],
                "End": True,
            },
            "Recovered": {
                "Type": "Pass",
                "Result": "recovered-after-retries",
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine_with_role(ctx, definition, role_arn)
    desc = _run_execution(ctx, sm_arn, input_data={"n": 1}, timeout_s=120)
    assert desc["status"] == "SUCCEEDED", (
        f"Expected SUCCEEDED via catch-after-retries, got {desc.get('status')}: {desc.get('cause')}"
    )
    output = _get_output(desc)
    assert output == "recovered-after-retries", (
        f"Expected the Catch-routed Pass state's output, got {output!r}"
    )
    # Retries must appear in history: 1 initial attempt + 2 retries = 3 schedulings.
    exec_arn = desc["executionArn"]
    events = _get_history_events(ctx, exec_arn)
    scheduled = [e for e in events if e["type"] in ("TaskScheduled", "LambdaFunctionScheduled")]
    assert len(scheduled) >= 3, (
        f"Expected >=3 task attempts (1 initial + 2 retries) in history, "
        f"got {len(scheduled)}: {[e['type'] for e in events]}"
    )


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
