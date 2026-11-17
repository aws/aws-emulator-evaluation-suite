"""lambda-invoke-task-awaits-a-slow-function-then-succeeds-with-its-payload."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-invoke-task-awaits-a-slow-function-then-succeeds-with-its-payload"
GROUP = "execution-lifecycle"
SERVICES = ["lambda", "stepfunctions"]

_SLEEP_SECONDS = 15
_FUNCTION_TIMEOUT_S = 35
_TASK_TIMEOUT_S = 300
_PAYLOAD = {"greeting": "hello from the function"}

_HANDLER_SRC = (
    "import time\n"
    "def handler(event, context):\n"
    f"    time.sleep({_SLEEP_SECONDS})\n"
    f"    return {_PAYLOAD!r}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A lambda:invoke Task with a TimeoutSeconds far longer than the function's own duration
    waits for the function to finish and ends SUCCEEDED carrying its exact payload.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role = _lambda_role(ctx, iam)
    _, fn_arn = _create_function(ctx, lam, fn_role)
    sm_role = _make_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])
    _, sm_arn = _create_state_machine(ctx, sfn, _definition(fn_arn), sm_role)

    exec_name = "sim2real-x-" + uuid.uuid4().hex[:12]
    final, exec_name = _await_role_assumable(sfn, sm_arn, exec_name)
    ctx.on_cleanup(lambda: _stop_if_running(sfn, final["executionArn"]))

    assert final["executionArn"].endswith(f":{exec_name}"), (
        f"DescribeExecution's executionArn must carry the name the check started it under "
        f"({exec_name!r}); got {final['executionArn']!r}"
    )
    assert final["status"] == "SUCCEEDED", (
        f"the execution must end SUCCEEDED once the {_SLEEP_SECONDS}s function returns, not time "
        f"out against the Task's {_TASK_TIMEOUT_S}s budget; got {final['status']!r}, cause "
        f"{(final.get('cause') or '')[:300]!r}"
    )
    output = json.loads(final["output"])
    assert output["Payload"] == _PAYLOAD, (
        f"the execution's output must carry the function's own payload {_PAYLOAD!r} unchanged; "
        f"got {output.get('Payload')!r}"
    )


def _definition(fn_arn: str) -> str:
    """One lambda:invoke Task whose TimeoutSeconds is well past the function's own duration."""
    return json.dumps({
        "StartAt": "Invoke",
        "States": {"Invoke": {
            "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
            "TimeoutSeconds": _TASK_TIMEOUT_S,
            "End": True,
        }},
    })


_TAGS = {"sim2real:managed": "true", "sim2real": CHECK[:200]}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_SFN_TAGLIST = [{"key": k, "value": v} for k, v in _TAGS.items()]
_FN_CREATE_TIMEOUT_S = 240
_TRUST_BARRIER_TIMEOUT_S = 240


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _zip_handler(src: str) -> bytes:
    """A one-file deployment package built in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _make_role(ctx, iam, service, statements):
    """One tagged role trusted by one AWS service with one inline policy; cleanups registered LIFO."""
    name = ctx.unique_name("sim2real-scn-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_TAGLIST,
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


def _lambda_role(ctx, iam):
    """The function's execution role: CloudWatch Logs only."""
    return _make_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                       "logs:PutLogEvents"], "Resource": "*"}])


def _create_function(ctx, lam, role_arn):
    """Create the sleeping-handler function, retrying while a fresh role is not yet assumable."""
    name = ctx.unique_name("sim2real-scn-fn-")
    deadline = time.monotonic() + _FN_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="handler.handler", Code={"ZipFile": _zip_handler(_HANDLER_SRC)},
                Timeout=_FUNCTION_TIMEOUT_S, MemorySize=128, Tags=_TAGS,
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc.response["Error"]
            time.sleep(5.0)
            continue
        # LIFO: the log group's reap is registered first so it runs after the function's delete.
        ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
        ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                                 "ResourceNotFoundException"))
        lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        return name, arn
    raise AssertionError(
        f"no Lambda became creatable within {_FN_CREATE_TIMEOUT_S}s; last error {last!r}"
    )


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; raise if it keeps returning."""
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
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _create_state_machine(ctx, sfn, definition, role_arn):
    """A tagged STANDARD state machine; its delete is registered at once."""
    name = ctx.unique_name("sim2real-scn-sm-")
    arn = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn,
                                   type="STANDARD", tags=_SFN_TAGLIST)["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                             "StateMachineDoesNotExist"))
    return name, arn


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=2.0, description="condition"):
    """Bounded poll against a clock deadline; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# Failures of the fresh execution role's trust or invoke grant not yet propagated.
_PROPAGATION_NEEDLES = ("not authorized to assume", "UnrecognizedClientException", "AccessDeniedException")


def _await_role_assumable(sfn, sm_arn, exec_name):
    """Start executions until one ends other than in an IAM propagation failure, and return its
    DescribeExecution: a new role and its grant are not usable by Step Functions at once."""
    deadline = time.monotonic() + _TRUST_BARRIER_TIMEOUT_S
    last = {}
    while time.monotonic() < deadline:
        ex = sfn.start_execution(stateMachineArn=sm_arn, name=exec_name)["executionArn"]
        last = _poll_until(
            lambda: sfn.describe_execution(executionArn=ex),
            lambda d: d["status"] != "RUNNING",
            timeout_s=_FUNCTION_TIMEOUT_S + 120.0,
            description=f"execution {ex} reached a terminal status",
        )
        cause = last.get("cause") or ""
        if last["status"] != "FAILED" or not any(n in cause for n in _PROPAGATION_NEEDLES):
            return last, exec_name
        exec_name = "sim2real-x-" + uuid.uuid4().hex[:12]
        time.sleep(5.0)
    raise AssertionError(
        f"executions still failed on IAM propagation after {_TRUST_BARRIER_TIMEOUT_S}s: "
        f"last status {last.get('status')!r}, cause {(last.get('cause') or '')[:300]!r}"
    )


def _stop_if_running(sfn, exec_arn: str) -> None:
    try:
        status = sfn.describe_execution(executionArn=exec_arn)["status"]
        if status == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
