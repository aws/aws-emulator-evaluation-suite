"""task-credentials-external-id-mismatch-and-too-short-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-credentials-external-id-mismatch-and-too-short-rejected"
GROUP = "authorization"
SERVICES = ["lambda", "stepfunctions"]

_OK_SRC = (
    "def handler(event, context):\n"
    "    return {'ok': True}\n"
)

_ASSUME_RACE_NEEDLE = "not authorized to assume the task state's role"
_TOKEN_PROPAGATION_NEEDLE = "UnrecognizedClientException"


def _zip_handler(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _make_role(ctx, iam, principal, statements, *, condition=None):
    """One role trusting ``principal`` (a service name or an IAM ARN), one inline policy.

    Referencing a role just created as another role's trust ``Principal`` races IAM's own
    propagation and answers ``MalformedPolicyDocument`` until it clears.
    """
    name = ctx.unique_name("sim2real-scn-role-")
    key = "Service" if isinstance(principal, str) and principal.endswith(".amazonaws.com") else "AWS"
    stmt = {"Effect": "Allow", "Principal": {key: principal}, "Action": "sts:AssumeRole"}
    if condition:
        stmt["Condition"] = condition
    deadline = time.monotonic() + 60.0
    arn = None
    while True:
        try:
            arn = iam.create_role(
                RoleName=name,
                AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [stmt]}),
                Tags=[{"Key": "sim2real", "Value": "task-credentials-external-id-rejected"}],
            )["Role"]["Arn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() > deadline:
                raise
            time.sleep(3.0)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="inline",
                            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


_FN_CREATE_TIMEOUT_S = 240


def _create_function(ctx, lam, src, role_arn):
    """Create an inline-source function, retrying the wait at FIRST USE of a fresh role."""
    name = ctx.unique_name("sim2real-scn-fn-")
    deadline = time.monotonic() + _FN_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="handler.handler", Code={"ZipFile": _zip_handler(src)},
                Timeout=20, MemorySize=128, Tags={"sim2real": "task-credentials-external-id-rejected"},
            )["FunctionArn"]
            ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            lam.get_waiter("function_active_v2").wait(
                FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
            return name, arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc.response["Error"]
            time.sleep(5.0)
    raise AssertionError(f"no Lambda became creatable within {_FN_CREATE_TIMEOUT_S}s; last error {last!r}")


def _reap_log_group(ctx, name: str, *, reads: int = 4, interval_s: float = 2.0,
                    budget_s: float = 120.0) -> None:
    logs = ctx.client("logs")
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        exists = any(
            g["logGroupName"] == name
            for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name)
            for g in page.get("logGroups") or []
        )
        if exists:
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
                    f"log group {name!r} still coming back after {budget_s}s of deletes; "
                    f"{absent} clean read(s) so far"
                )
            time.sleep(interval_s)


def _run_past_assume_race(sfn, sm_arn, input_json, *, rounds=20, interval_s=3.0, name_prefix="sim2real-x-"):
    """Retries only while the response is the trust-propagation race.

    A genuine, permanent denial carries the SAME wording as that race — AWS does not
    distinguish them in the message — so after the bound is exhausted the last response IS
    the answer, whichever one it turns out to be. A freshly-assumed session token not yet
    recognized by Lambda is a second, distinct propagation window retried the same way.
    """
    last = None
    for i in range(rounds):
        last = sfn.start_sync_execution(
            stateMachineArn=sm_arn, name=f"{name_prefix}{i}", input=input_json)
        cause = last.get("cause") or ""
        if last.get("status") == "FAILED" and (
            _ASSUME_RACE_NEEDLE in cause or _TOKEN_PROPAGATION_NEEDLE in cause
        ):
            time.sleep(interval_s)
            continue
        return last
    return last


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Task's ``Credentials`` role rejects an ExternalId that does not match its trust
    condition, and rejects one shorter than STS's own 2-character minimum before ever
    attempting the assumption.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/tutorial-access-cross-acct-resources.html
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role_name, fn_role_arn = _make_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                       "logs:PutLogEvents"], "Resource": "*"}])
    _, fn_arn = _create_function(ctx, lam, _OK_SRC, fn_role_arn)

    exec_role_name, exec_role_arn = _make_role(ctx, iam, "states.amazonaws.com", [])

    # One state machine with no ExternalId field (the POSITIVE CONTROL and the MISMATCH share
    # it, their task role supplied at runtime); a second always carries ExternalId.$ for the
    # too-short case, since a literal ExternalId is rejected at CreateStateMachine time.
    no_override_def = json.dumps({
        "StartAt": "Invoke",
        "States": {"Invoke": {
            "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
            "Credentials": {"RoleArn.$": "$.roleArn"},
            "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
            "End": True,
        }}
    })
    override_def = json.dumps({
        "StartAt": "Invoke",
        "States": {"Invoke": {
            "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
            "Credentials": {"RoleArn.$": "$.roleArn", "ExternalId.$": "$.extid"},
            "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
            "End": True,
        }}
    })

    def create_sm(definition):
        name = ctx.unique_name("sim2real-scn-sm-")
        arn = sfn.create_state_machine(
            name=name, definition=definition, roleArn=exec_role_arn, type="EXPRESS",
            tags=[{"key": "sim2real", "value": "task-credentials-external-id-rejected"}],
        )["stateMachineArn"]
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn

    no_override_sm_arn = create_sm(no_override_def)
    override_sm_arn = create_sm(override_def)

    ok_task_role_name, ok_task_role_arn = _make_role(
        ctx, iam, exec_role_arn,
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])

    mismatch_expected_ext_id = ctx.unique_name("sim2real-scn-expected-extid-")
    mismatch_task_role_name, mismatch_task_role_arn = _make_role(
        ctx, iam, exec_role_arn,
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}],
        condition={"StringEquals": {"sts:ExternalId": mismatch_expected_ext_id}})

    too_short_task_role_name, too_short_task_role_arn = _make_role(
        ctx, iam, exec_role_arn,
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])

    iam.put_role_policy(RoleName=exec_role_name, PolicyName="assume-task-roles", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
        "Resource": [ok_task_role_arn, mismatch_task_role_arn, too_short_task_role_arn]}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=exec_role_name, PolicyName="assume-task-roles"))

    # POSITIVE CONTROL: a role with no ExternalId condition succeeds, which also clears the
    # exec role's own assume-role propagation before the two negatives below are asserted.
    control = _run_past_assume_race(
        sfn, no_override_sm_arn, json.dumps({"roleArn": ok_task_role_arn}),
        name_prefix="sim2real-ctl-")
    assert control["status"] == "SUCCEEDED", (
        f"the unconditioned task role must succeed as a control, got {control['status']!r} / "
        f"{control.get('error')!r}: {control.get('cause')!r}"
    )
    assert json.loads(control["output"])["Payload"]["ok"] is True, (
        f"expected the function's payload in the control's output, got {control.get('output')!r}"
    )

    # MISMATCH: no Credentials.ExternalId override, so Step Functions passes its default (this
    # state machine's own ARN) — which never equals what the role's trust condition requires.
    mismatch = _run_past_assume_race(
        sfn, no_override_sm_arn, json.dumps({"roleArn": mismatch_task_role_arn}),
        name_prefix="sim2real-mismatch-")
    assert mismatch["status"] == "FAILED", (
        f"an ExternalId the trust condition never grants must fail, got {mismatch['status']!r}"
    )
    assert mismatch["error"] == "States.TaskFailed", (
        f"a denied role assumption surfaces as States.TaskFailed, got {mismatch['error']!r}: "
        f"{mismatch.get('cause')!r}"
    )
    assert mismatch["cause"] == (
        f"The role {exec_role_arn} is not authorized to assume the task state's role, "
        f"{mismatch_task_role_arn}."
    ), f"unexpected cause for the ExternalId mismatch: {mismatch.get('cause')!r}"
    assert "output" not in mismatch, f"a denied execution produces no output, got {mismatch.get('output')!r}"

    # TOO SHORT: a 1-character ExternalId is rejected by STS's own 2-1224 character bound
    # before Step Functions ever attempts the assumption — no propagation race to retry past.
    too_short = sfn.start_sync_execution(
        stateMachineArn=override_sm_arn, name=ctx.unique_name("sim2real-short-"),
        input=json.dumps({"roleArn": too_short_task_role_arn, "extid": "a"}))
    assert too_short["status"] == "FAILED", (
        f"a 1-character ExternalId must be rejected, got {too_short['status']!r}"
    )
    assert too_short["error"] == "States.Runtime", (
        f"a malformed Credentials map fails as States.Runtime, got {too_short['error']!r}: "
        f"{too_short.get('cause')!r}"
    )
    assert too_short["cause"] == (
        "An error occurred while executing the state 'Invoke' (entered at the event id #2). "
        f'The Credentials \'{{"ExternalId":"a","RoleArn":"{too_short_task_role_arn}"}}\' could '
        "not be used to start the Task: ['ExternalId' must be between 2 and 1224 characters, "
        "containing only letters, numbers, plus (+), equals (=), comma (,), period (.), at (@), "
        "colon (:), forward slash (/), and hyphen (-)]"
    ), f"unexpected cause for the too-short ExternalId: {too_short.get('cause')!r}"
    assert "output" not in too_short, f"a rejected execution produces no output, got {too_short.get('output')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
