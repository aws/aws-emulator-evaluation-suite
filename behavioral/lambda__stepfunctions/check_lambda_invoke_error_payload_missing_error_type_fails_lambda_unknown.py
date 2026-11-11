"""lambda-invoke-error-payload-missing-error-type-fails-lambda-unknown."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-invoke-error-payload-missing-error-type-fails-lambda-unknown"
GROUP = "error_handling"
SERVICES = ["lambda", "stepfunctions"]

_NO_TYPE_MESSAGE = "sim2real: custom runtime error report with no errorType field"
_WITH_TYPE_MESSAGE = "sim2real: custom runtime error report with an errorType field"
_CUSTOM_ERROR_TYPE = "sim2real.CustomReportedError"

# A minimal custom runtime: for "ok" it posts a normal /response; for "no_type" it posts to
# /error an ErrorRequest body that OMITS errorType entirely; for "with_type" it posts one that
# carries errorType, so the only variable between the two failing runs is that one field.
_BOOTSTRAP = (
    "#!/bin/sh\n"
    "set -eu\n"
    "while true; do\n"
    '  HEADERS="$(mktemp)"\n'
    '  curl -sS -D "$HEADERS" -o /tmp/event.json '
    '"http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next"\n'
    "  REQUEST_ID=$(grep -Fi Lambda-Runtime-Aws-Request-Id \"$HEADERS\" | tr -d '\\r' "
    "| cut -d: -f2 | tr -d ' ')\n"
    '  if grep -q "\\"mode\\": *\\"no_type\\"" /tmp/event.json; then\n'
    f'    curl -sS -X POST "http://${{AWS_LAMBDA_RUNTIME_API}}/2018-06-01/runtime/invocation/'
    '$REQUEST_ID/error" -H "Lambda-Runtime-Function-Error-Type: Unhandled" '
    f"""-d '{{"errorMessage": "{_NO_TYPE_MESSAGE}"}}'\n"""
    '  elif grep -q "\\"mode\\": *\\"with_type\\"" /tmp/event.json; then\n'
    f'    curl -sS -X POST "http://${{AWS_LAMBDA_RUNTIME_API}}/2018-06-01/runtime/invocation/'
    '$REQUEST_ID/error" -H "Lambda-Runtime-Function-Error-Type: Unhandled" '
    f"""-d '{{"errorMessage": "{_WITH_TYPE_MESSAGE}", "errorType": "{_CUSTOM_ERROR_TYPE}"}}'\n"""
    "  else\n"
    '    curl -sS -X POST "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/'
    '$REQUEST_ID/response" -d \'{"ok": true}\'\n'
    "  fi\n"
    "done\n"
)


@tags("axis:happy-path", "cap:c3", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A lambda:invoke Task whose function reports an Unhandled error with NO errorType field
    fails the execution with error Lambda.Unknown and a cause naming the returned payload, while
    the identical wiring reporting an errorType surfaces that name instead.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role = _create_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                        "logs:PutLogEvents"], "Resource": "*"}])
    fn_name, fn_arn = _create_function(ctx, lam, fn_role)

    sm_role = _create_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])
    sm_arn = _create_state_machine(ctx, sfn, _definition(fn_arn), sm_role)

    # Positive control: the SAME wiring, over a successful response, still reaches SUCCEEDED —
    # this also absorbs the IAM role-trust propagation race before any failing run is graded.
    ok = _run_to_terminal(ctx, sfn, sm_arn, {"mode": "ok"}, timeout_s=150)
    assert ok["status"] == "SUCCEEDED", (
        f"positive control (a normal response) must succeed, got {ok['status']!r} "
        f"error={ok.get('error')!r} cause={ok.get('cause')!r}"
    )
    assert json.loads(ok["output"])["Payload"] == {"ok": True}, (
        f"positive control's response did not arrive intact: {ok['output']!r}"
    )

    # Break exactly one thing: the error report carries no errorType.
    no_type = _run_to_terminal(ctx, sfn, sm_arn, {"mode": "no_type"}, timeout_s=90)
    assert no_type["status"] == "FAILED", (
        f"a function error with no errorType must FAIL the execution; got {no_type['status']!r}"
    )
    assert no_type.get("error") == "Lambda.Unknown", (
        f"a function error carrying no errorType must surface as Lambda.Unknown, got "
        f"{no_type.get('error')!r} with cause {no_type.get('cause')!r}"
    )
    returned_payload = json.dumps({"errorMessage": _NO_TYPE_MESSAGE}, separators=(",", ":"))
    expected_cause = (
        "The cause could not be determined because Lambda did not return an error type. "
        f"Returned payload: {returned_payload}"
    )
    assert no_type.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {no_type.get('cause')!r}"
    )

    # Differential control: identical wiring, but the report now carries an errorType — the
    # TaskFailed error becomes that name verbatim, never Lambda.Unknown.
    with_type = _run_to_terminal(ctx, sfn, sm_arn, {"mode": "with_type"}, timeout_s=90)
    assert with_type["status"] == "FAILED", (
        f"a function error with an errorType must FAIL the execution too; got "
        f"{with_type['status']!r}"
    )
    assert with_type.get("error") == _CUSTOM_ERROR_TYPE, (
        f"a function error carrying errorType={_CUSTOM_ERROR_TYPE!r} must surface under that "
        f"exact name, not Lambda.Unknown; got {with_type.get('error')!r}"
    )
    expected_with_type_cause = json.dumps(
        {"errorMessage": _WITH_TYPE_MESSAGE, "errorType": _CUSTOM_ERROR_TYPE},
        separators=(",", ":"),
    )
    assert with_type.get("cause") == expected_with_type_cause, (
        f"expected cause {expected_with_type_cause!r}, got {with_type.get('cause')!r}"
    )


def _definition(fn_arn: str) -> str:
    """One Task invoking the probe function with no Catch, so the raw error/cause survives."""
    return json.dumps({
        "StartAt": "Invoke",
        "States": {"Invoke": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
            "End": True,
        }},
    })


def _zip_bootstrap() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        zi = zipfile.ZipInfo("bootstrap")
        zi.external_attr = 0o755 << 16
        z.writestr(zi, _BOOTSTRAP)
    return buf.getvalue()


def _create_role(ctx, iam, principal, statements):
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


_FN_CREATE_TIMEOUT_S = 240


def _create_function(ctx, lam, role_arn):
    """Create a 128MB custom-runtime (provided.al2023) function, retrying while a fresh role is
    not yet assumable by Lambda."""
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + _FN_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="provided.al2023", Role=role_arn,
                Handler="irrelevant.handler", Code={"ZipFile": _zip_bootstrap()},
                Timeout=10, MemorySize=128, Tags={"sim2real": CHECK},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc.response["Error"]
            time.sleep(5.0)
            continue
        # LIFO: the log-group reap is registered first so it runs after the function's delete.
        ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
        ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                                 "ResourceNotFoundException"))
        lam.get_waiter("function_active_v2").wait(
            FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        return name, arn
    raise AssertionError(
        f"no Lambda became creatable within {_FN_CREATE_TIMEOUT_S}s; last error {last!r}"
    )


def _reap_log_group(ctx, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    logs = ctx.client("logs")
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


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


_SM_CREATE_TIMEOUT_S = 120


def _create_state_machine(ctx, sfn, definition, role_arn):
    """CreateStateMachine, retrying only the AccessDeniedException a fresh role's trust has not
    yet propagated past."""
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + _SM_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc.response["Error"]
            time.sleep(3.0)
            continue
        ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                                 "StateMachineDoesNotExist"))
        return arn
    raise AssertionError(
        f"CreateStateMachine still AccessDenied {_SM_CREATE_TIMEOUT_S}s after role creation; "
        f"last error {last!r}"
    )


_IAM_RACE_MARKERS = (
    "not authorized to assume",
    "UnrecognizedClientException",
    "security token included in the request is invalid",
)

def _run_to_terminal(ctx, sfn, sm_arn, payload, *, timeout_s: float):
    """Start one execution and poll DescribeExecution every 2s to a terminal status, retrying the
    start itself while the state machine's role is not yet assumable by Step Functions."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-x-"),
            input=json.dumps(payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
        inner_deadline = time.monotonic() + 60.0
        while True:
            last = sfn.describe_execution(executionArn=exec_arn)
            if last["status"] != "RUNNING":
                break
            if time.monotonic() >= inner_deadline:
                raise AssertionError(f"execution {exec_arn} still RUNNING after 60s: {last!r}")
            time.sleep(2.0)
        blob = last.get("cause") or ""
        if last["status"] != "FAILED" or not any(m in blob for m in _IAM_RACE_MARKERS):
            return last
        time.sleep(5.0)
    raise AssertionError(f"execution never left the role-trust race within {timeout_s}s: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
