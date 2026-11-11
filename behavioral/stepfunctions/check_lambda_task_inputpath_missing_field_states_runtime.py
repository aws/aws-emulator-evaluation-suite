"""lambda-task-inputpath-missing-field-states-runtime."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-task-inputpath-missing-field-states-runtime"
GROUP = "express_workflows"
SERVICES = ["stepfunctions", "lambda"]

_INPUT_PATH = "$.missing"
_HANDLER = (
    "def lambda_handler(event, context):\n"
    "    return {'echo': event}\n"
)


def _trust_policy(principal: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": principal},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_role(ctx, principal: str, statements=None) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnip-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy(principal),
        Path="/sim2real/",
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pname)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=name,
            PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return arn


def _reap_log_group(ctx, name: str) -> None:
    """Delete the function's log group and keep deleting until it stays gone.

    A buffered flush can recreate it after one delete, so one call is one round,
    not a teardown.
    """
    logs = ctx.client("logs")
    absent_rounds = 0
    for _ in range(8):
        try:
            logs.delete_log_group(logGroupName=name)
            absent_rounds = 0
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            absent_rounds += 1
            if absent_rounds >= 2:
                return
        time.sleep(2)
    raise RuntimeError(f"log group {name} kept reappearing")


def _create_lambda(ctx) -> str:
    lam = ctx.client("lambda")
    role_arn = _create_role(ctx, "lambda.amazonaws.com")
    fn_name = ctx.unique_name("sim2real-behav-sfnipfn-")
    # Registered BEFORE the create, so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{fn_name}"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", _HANDLER)
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=10,
                MemorySize=128,
                Description="sim2real-behav sfn inputpath task target",
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" \
                    or "assume" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(2.0)
    deadline = time.monotonic() + 90.0
    while True:
        state = lam.get_function_configuration(FunctionName=fn_name)["State"]
        if state == "Active":
            return arn
        if time.monotonic() > deadline:
            raise AssertionError(f"function {fn_name} never became Active, last state {state!r}")
        time.sleep(2.0)


def _definition(fn_arn: str) -> str:
    return json.dumps(
        {
            "Comment": "a Lambda Task whose InputPath names a field absent from the input",
            "StartAt": "Route",
            "States": {
                "Route": {
                    "Type": "Choice",
                    "Choices": [
                        {"Variable": "$.mode", "StringEquals": "bad", "Next": "BadTask"}
                    ],
                    "Default": "GoodTask",
                },
                "GoodTask": {
                    "Type": "Task",
                    "Resource": fn_arn,
                    "End": True,
                },
                "BadTask": {
                    "Type": "Task",
                    "Resource": fn_arn,
                    "InputPath": _INPUT_PATH,
                    "End": True,
                },
            },
        }
    )


def _create_state_machine(ctx, definition: str, role_arn: str) -> str:
    """An EXPRESS state machine, retrying only the AccessDeniedException raised while the
    freshly created role's assume-role grant propagates, polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnip-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="EXPRESS",
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        f"CreateStateMachine(type=EXPRESS) still AccessDenied 120s after the role was "
        f"created. Last error: {last}"
    )


_IAM_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "security token included in the request is invalid",
)


def _start_sync_until_role_propagates(sfn, sm_arn: str, payload: dict, *, attempts=10):
    """StartSyncExecution, retrying only a fresh role's still-unpropagated assume-role grant."""
    result = None
    for _ in range(attempts):
        result = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps(payload))
        if result["status"] != "FAILED":
            return result
        if not any(m in (result.get("cause") or "") for m in _IAM_RACE_MARKERS):
            return result
        time.sleep(2.0)
    return result


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda Task whose InputPath names a field absent from its input fails the
    synchronous execution with States.Runtime and AWS's exact cause, carrying no output.
    """
    sfn = ctx.client("stepfunctions")
    fn_arn = _create_lambda(ctx)
    role_arn = _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": [fn_arn, f"{fn_arn}:*"]},
    ])
    sm_arn = _create_state_machine(ctx, _definition(fn_arn), role_arn)

    # --- Positive control: the same machine, the Default path with no InputPath ----
    ok = _start_sync_until_role_propagates(sfn, sm_arn, {"mode": "ok"})
    assert ok["status"] == "SUCCEEDED", (
        "the mode=ok path (no InputPath) must report SUCCEEDED — without this control "
        f"the failure assertions below cannot tell a working sync endpoint from one that "
        f"answers FAILED to everything; got {ok['status']!r} error={ok.get('error')!r} "
        f"cause={ok.get('cause')!r}"
    )
    assert json.loads(ok["output"])["echo"] == {"mode": "ok"}, (
        f"expected the function to echo its full input, got {ok['output']!r}"
    )

    # --- The subject: InputPath selects a field the input lacks --------------------
    try:
        bad = _start_sync_until_role_propagates(sfn, sm_arn, {"mode": "bad"})
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            "StartSyncExecution must report an InputPath runtime failure inside a "
            f"successful response carrying status=FAILED; it raised {err.get('Code')!r} "
            f"instead ({err.get('Message')!r})."
        ) from exc

    assert bad["status"] == "FAILED", (
        f"a Task whose InputPath selects an absent field must report status FAILED; "
        f"got {bad['status']!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"the sync response must carry error 'States.Runtime'; got {bad.get('error')!r}"
    )
    expected_cause = (
        "An error occurred while executing the state 'BadTask' (entered at the event "
        f"id #4). Invalid path '{_INPUT_PATH}' : No results for path: $['missing']"
    )
    assert bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {bad.get('cause')!r}"
    )
    assert "output" not in bad, (
        f"a FAILED synchronous Express execution has no output; it carried "
        f"output={bad.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
