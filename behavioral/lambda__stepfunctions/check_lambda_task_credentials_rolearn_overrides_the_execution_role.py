"""lambda-task-credentials-rolearn-overrides-the-execution-role."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-task-credentials-rolearn-overrides-the-execution-role"
GROUP = "task-credentials"
SERVICES = ["lambda", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Task's Credentials.RoleArn, not the execution role, is what Step Functions assumes to
    invoke the Lambda; without it the same execution role is denied the invoke it never held."""
    fn_arn = _create_lambda_function(ctx)

    # The execution role: trusted by the states service, and granted only sts:AssumeRole on
    # the task role below -- never lambda:InvokeFunction, so a Task with no Credentials would
    # be denied invoking the function directly.
    exec_role_name = ctx.unique_name("sim2real-role-")
    task_role_name = ctx.unique_name("sim2real-role-")

    # The execution role must exist before the task role can name it as a trusted principal.
    exec_role_arn = _create_role(ctx, exec_role_name, {"Service": "states.amazonaws.com"}, [])
    # The task role: trusted only by the execution role above (what Credentials.RoleArn makes
    # Step Functions actually assume), and the only identity holding lambda:InvokeFunction.
    task_role_arn = _create_role(
        ctx,
        task_role_name,
        {"AWS": exec_role_arn},
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}],
    )
    _put_policy(
        ctx,
        exec_role_name,
        f"{exec_role_name}-assume",
        [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": task_role_arn}],
    )

    with_creds_arn = _create_state_machine(
        ctx,
        {
            "StartAt": "Invoke",
            "States": {
                "Invoke": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {"FunctionName": fn_arn, "Payload": {}},
                    "Credentials": {"RoleArn": task_role_arn},
                    "ResultSelector": {"body.$": "$.Payload"},
                    "End": True,
                }
            },
        },
        exec_role_arn,
    )
    without_creds_arn = _create_state_machine(
        ctx,
        {
            "StartAt": "Invoke",
            "States": {
                "Invoke": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {"FunctionName": fn_arn, "Payload": {}},
                    "End": True,
                }
            },
        },
        exec_role_arn,
    )

    sfn = ctx.client("stepfunctions")

    # Positive: the Task's Credentials.RoleArn supplies the invoke permission the execution
    # role itself was never granted, so the execution succeeds.
    desc_with = _run_past_propagation(ctx, with_creds_arn, task_role_name)
    assert desc_with["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED using Credentials.RoleArn, got {desc_with['status']}: {desc_with.get('error')}"
    )
    assert json.loads(desc_with["output"])["body"] == {"ok": True}, desc_with

    # Negative control, identical wiring minus Credentials: the execution role alone holds no
    # lambda:InvokeFunction, so the same function invocation is denied.
    exec_without = sfn.start_execution(stateMachineArn=without_creds_arn, input="{}")["executionArn"]
    desc_without = _wait_execution_terminal(ctx, exec_without, timeout_s=90)
    assert desc_without["status"] == "FAILED", (
        f"expected FAILED without Credentials.RoleArn, got {desc_without['status']}: {desc_without!r}"
    )
    assert desc_without.get("error") == "Lambda.AWSLambdaException", desc_without
    # Everything here is known except the assumed-role session name Lambda's SDK call mints and
    # the request id AWS stamps on the denial -- both opaque, so matched by shape, not value.
    cause_pattern = (
        rf"^User: arn:aws:sts::{re.escape(ctx.account)}:assumed-role/{re.escape(exec_role_name)}/[A-Za-z0-9]+ "
        rf"is not authorized to perform: lambda:InvokeFunction on resource: {re.escape(fn_arn)} "
        r"because no identity-based policy allows the lambda:InvokeFunction action "
        r"\(Service: AWSLambda; Status Code: 403; Error Code: AccessDeniedException; "
        r"Request ID: [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}; Proxy: null\)$"
    )
    cause = desc_without.get("cause", "")
    assert re.fullmatch(cause_pattern, cause), f"cause did not match the expected shape: {cause!r}"


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_function(ctx) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    role_name = ctx.unique_name("sim2real-role-")
    role_arn = _create_role(ctx, role_name, {"Service": "lambda.amazonaws.com"}, [])
    code = "def handler(event, context):\n    return {'ok': True}\n"
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
                Timeout=15,
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


def _create_role(ctx, role_name, trust_principal, extra_statements):
    """Create ``role_name`` trusting ``trust_principal`` (a ``Principal`` value: a service
    string's ``{"Service": ...}`` or a role ARN's ``{"AWS": ...}``), with ``extra_statements``
    plus baseline log permissions. Returns the role's ARN."""
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": trust_principal, "Action": "sts:AssumeRole"}],
    }
    # A trust principal naming a role created moments ago can trail IAM's own read-after-write
    # consistency, surfacing as MalformedPolicyDocumentException on the very next CreateRole.
    for attempt in range(20):
        try:
            arn = iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust),
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )["Role"]["Arn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "MalformedPolicyDocument" and attempt < 19:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    statements = [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}
    ] + extra_statements
    _put_policy(ctx, role_name, f"{role_name}-policy", statements)
    return arn


def _put_policy(ctx, role_name, policy_name, statements):
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements})
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"))


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


# Failures of a fresh role's trust or token, or of its fresh invoke grant, not yet propagated.
_PROPAGATION_NEEDLES = ("not authorized to assume", "UnrecognizedClientException")


def _is_propagation_failure(desc, task_role_name) -> bool:
    cause = desc.get("cause") or ""
    if any(n in cause for n in _PROPAGATION_NEEDLES):
        return True
    return "AccessDeniedException" in cause and f"assumed-role/{task_role_name}/" in cause


def _run_past_propagation(ctx, sm_arn, task_role_name, timeout_s=120.0, interval_s=3.0):
    """Start executions until one ends other than in an IAM propagation failure and return its
    description; raises when propagation has not settled by the deadline."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last_desc = None
    while time.monotonic() < deadline:
        exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
        last_desc = _wait_execution_terminal(ctx, exec_arn, timeout_s=30)
        if last_desc["status"] != "FAILED" or not _is_propagation_failure(last_desc, task_role_name):
            return last_desc
        time.sleep(interval_s)
    raise AssertionError(f"executions still failed on IAM propagation after {timeout_s}s: {last_desc}")


def _wait_execution_terminal(ctx, exec_arn, timeout_s=90, poll_s=2):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = sfn.describe_execution(executionArn=exec_arn)
    while desc["status"] == "RUNNING" and time.monotonic() < deadline:
        time.sleep(poll_s)
        desc = sfn.describe_execution(executionArn=exec_arn)
    if desc["status"] == "RUNNING":
        raise AssertionError(f"execution still RUNNING after {timeout_s}s")
    return desc


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
