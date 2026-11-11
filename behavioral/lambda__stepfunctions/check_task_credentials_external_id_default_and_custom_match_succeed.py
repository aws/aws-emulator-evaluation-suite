"""task-credentials-external-id-default-and-custom-match-succeed."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-credentials-external-id-default-and-custom-match-succeed"
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
                Tags=[{"Key": "sim2real", "Value": "task-credentials-external-id"}],
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
                Timeout=20, MemorySize=128, Tags={"sim2real": "task-credentials-external-id"},
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


_SM_CREATE_TIMEOUT_S = 120


def _create_state_machine(ctx, sfn, definition, exec_role_arn):
    """CreateStateMachine, retrying only the AccessDeniedException a fresh execution role's trust
    answers until it propagates."""
    name = ctx.unique_name("sim2real-scn-sm-")
    deadline = time.monotonic() + _SM_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=exec_role_arn, type="EXPRESS",
                tags=[{"key": "sim2real", "value": "task-credentials-external-id"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc.response["Error"]
            time.sleep(3.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return name, arn
    raise AssertionError(
        f"CreateStateMachine still AccessDenied {_SM_CREATE_TIMEOUT_S}s after role creation; "
        f"last error {last!r}"
    )


def _run_past_assume_race(sfn, sm_arn, input_json, *, rounds=20, interval_s=3.0, name_prefix="sim2real-x-"):
    """Retries only while the response is a propagation race — the role's trust not yet
    recognized, or its freshly-assumed session token not yet recognized by Lambda; the end is
    the task's actual decision — under test here. Raises when the race outlasts the rounds.
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
    raise AssertionError(
        f"executions still failed on IAM propagation after {rounds} rounds: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Task's assumed ``Credentials`` role: the ExternalId Step Functions passes by default
    is the state machine's own ARN, a caller-supplied override replaces it (so that role then
    refuses), and a role with no ExternalId condition accepts either way.

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

    # One state machine with no ExternalId field in its Credentials, whose task role ARN is
    # supplied at runtime — shared by the "default equals the state machine ARN" and the
    # "no condition at all" scenarios below.
    no_override_def = json.dumps({
        "StartAt": "Invoke",
        "States": {"Invoke": {
            "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
            "Credentials": {"RoleArn.$": "$.roleArn"},
            "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
            "End": True,
        }}
    })

    # A second state machine whose Credentials ALSO supplies a caller ExternalId at runtime —
    # custom ExternalId is only accepted through the ``.$`` reference form, never a literal.
    override_def = json.dumps({
        "StartAt": "Invoke",
        "States": {"Invoke": {
            "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
            "Credentials": {"RoleArn.$": "$.roleArn", "ExternalId.$": "$.extid"},
            "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
            "End": True,
        }}
    })

    _, no_override_sm_arn = _create_state_machine(ctx, sfn, no_override_def, exec_role_arn)
    _, override_sm_arn = _create_state_machine(ctx, sfn, override_def, exec_role_arn)

    default_task_role_name, default_task_role_arn = _make_role(
        ctx, iam, exec_role_arn,
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}],
        condition={"StringEquals": {"sts:ExternalId": no_override_sm_arn}},
    )

    custom_ext_id = ctx.unique_name("sim2real-scn-extid-")
    custom_task_role_name, custom_task_role_arn = _make_role(
        ctx, iam, exec_role_arn,
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}],
        condition={"StringEquals": {"sts:ExternalId": custom_ext_id}},
    )

    no_condition_task_role_name, no_condition_task_role_arn = _make_role(
        ctx, iam, exec_role_arn,
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])

    iam.put_role_policy(RoleName=exec_role_name, PolicyName="assume-task-roles", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
        "Resource": [default_task_role_arn, custom_task_role_arn, no_condition_task_role_arn]}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=exec_role_name, PolicyName="assume-task-roles"))

    # (1) DEFAULT: no Credentials.ExternalId in the ASL. The role's trust condition requires
    # ExternalId == this state machine's own ARN, so success proves Step Functions passed it.
    default_result = _run_past_assume_race(
        sfn, no_override_sm_arn, json.dumps({"roleArn": default_task_role_arn}),
        name_prefix="sim2real-default-")
    assert default_result["status"] == "SUCCEEDED", (
        f"a role conditioned on ExternalId == the state machine's own ARN must accept the "
        f"default Step Functions passes, got {default_result['status']!r} / "
        f"{default_result.get('error')!r}: {default_result.get('cause')!r}"
    )
    assert json.loads(default_result["output"])["Payload"]["ok"] is True, (
        f"expected the function's payload in the output, got {default_result.get('output')!r}"
    )

    # (2) CUSTOM MATCH: Credentials.ExternalId.$ supplies a caller value that equals what the
    # role's trust condition requires, overriding the default.
    custom_result = _run_past_assume_race(
        sfn, override_sm_arn,
        json.dumps({"roleArn": custom_task_role_arn, "extid": custom_ext_id}),
        name_prefix="sim2real-custom-")
    assert custom_result["status"] == "SUCCEEDED", (
        f"a caller-supplied ExternalId matching the role's trust condition must succeed, got "
        f"{custom_result['status']!r} / {custom_result.get('error')!r}: {custom_result.get('cause')!r}"
    )
    assert json.loads(custom_result["output"])["Payload"]["ok"] is True, (
        f"expected the function's payload in the output, got {custom_result.get('output')!r}"
    )

    # (3) NOT NEEDED: the role's trust policy carries no ExternalId condition at all, so the
    # default Step Functions still passes is simply ignored rather than required.
    no_condition_result = _run_past_assume_race(
        sfn, no_override_sm_arn, json.dumps({"roleArn": no_condition_task_role_arn}),
        name_prefix="sim2real-nocond-")
    assert no_condition_result["status"] == "SUCCEEDED", (
        f"a role with no ExternalId condition must accept the assumption regardless, got "
        f"{no_condition_result['status']!r} / {no_condition_result.get('error')!r}: "
        f"{no_condition_result.get('cause')!r}"
    )
    assert json.loads(no_condition_result["output"])["Payload"]["ok"] is True, (
        f"expected the function's payload in the output, got {no_condition_result.get('output')!r}"
    )

    # (4) OVERRIDE REPLACES THE DEFAULT: the role (1) assumed, now through the state machine that
    # supplies Credentials.ExternalId.$, receives the caller value instead of the state machine's
    # ARN and refuses. Its trust already propagated in (1), so one run decides.
    replaced = sfn.start_sync_execution(
        stateMachineArn=override_sm_arn, name=ctx.unique_name("sim2real-replaced-"),
        input=json.dumps({"roleArn": default_task_role_arn, "extid": custom_ext_id}))
    assert replaced["status"] == "FAILED", (
        f"a supplied ExternalId replaces the default, so a role conditioned on the state machine's "
        f"ARN must refuse it, got {replaced['status']!r}"
    )
    assert replaced.get("error") == "States.TaskFailed", (
        f"a denied role assumption surfaces as States.TaskFailed, got {replaced.get('error')!r}: "
        f"{replaced.get('cause')!r}"
    )
    assert replaced.get("cause") == (
        f"The role {exec_role_arn} is not authorized to assume the task state's role, "
        f"{default_task_role_arn}."
    ), f"unexpected cause for the replaced ExternalId: {replaced.get('cause')!r}"
    assert "output" not in replaced, f"a denied execution produces no output, got {replaced.get('output')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
