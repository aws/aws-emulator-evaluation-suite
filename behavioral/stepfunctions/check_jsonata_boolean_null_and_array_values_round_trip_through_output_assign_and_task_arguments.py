"""jsonata-boolean-null-and-array-values-round-trip-through-output-assign-and-task-arguments."""

from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonata-boolean-null-and-array-values-round-trip-through-output-assign-and-task-arguments"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


# ===== helpers =====
_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(
    logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0
) -> None:
    """Delete log group `name` until `reads` consecutive reads find it absent.

    A single delete races a post-delete flush that recreates the group; retry until it converges.
    """
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
                    f"log group {name!r} still present after {budget_s}s of deletes; "
                    f"{absent} clean read(s) so far"
                )
            time.sleep(interval_s)


def _create_echo_lambda(ctx):
    """A Lambda that returns its event verbatim, so Arguments.Payload is traceable end to end."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-behav-lrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="Behavioral SFN JSONata echo Lambda execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"), "NoSuchEntity"
        )
    )

    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def lambda_handler(event, context):\n    return event\n")

    fn_name = ctx.unique_name("sim2real-behav-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{fn_name}"))
    deadline = time.monotonic() + 40
    last_err = None
    arn = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_buf.getvalue()},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
            ctx.on_cleanup(
                _teardown(
                    lambda: lam.delete_function(FunctionName=fn_name), "ResourceNotFoundException"
                )
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = exc
            time.sleep(3)
    if arn is None:
        raise last_err or RuntimeError(f"failed to create Lambda {fn_name}")

    wait_deadline = time.monotonic() + 60
    while time.monotonic() < wait_deadline:
        if lam.get_function_configuration(FunctionName=fn_name)["State"] == "Active":
            return fn_name, arn
        time.sleep(2)
    raise AssertionError(f"Lambda {fn_name} never became Active")


def _create_sfn_role_for_lambda(ctx, lambda_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="Behavioral SFN JSONata execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="invoke-lambda",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "lambda:InvokeFunction",
                        "Resource": [lambda_arn, lambda_arn + ":*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="invoke-lambda"),
            "NoSuchEntity",
        )
    )
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s, max_attempts=6):
    sfn = ctx.client("stepfunctions")
    desc = None
    for attempt in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_data),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            desc = sfn.describe_execution(executionArn=exec_arn)
            if desc["status"] != "RUNNING":
                break
            time.sleep(1)
        else:
            raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5 + attempt * 3)
    return desc


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


# ===== end helpers =====


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A JSONata boolean, null and array survive Assign across two states and Task Arguments into
    a real Lambda call, and come back through $states.result verbatim with their JSON type intact.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/transforming-data.html
    """
    fn_name, fn_arn = _create_echo_lambda(ctx)
    role_arn = _create_sfn_role_for_lambda(ctx, fn_arn)

    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Seed",
        "States": {
            "Seed": {
                "Type": "Pass",
                "Assign": {"bv": "{% true %}", "nv": "{% null %}", "av": "{% [1, 'two', 3.5] %}"},
                "Output": "{% $states.input %}",
                "Next": "Through",
            },
            "Through": {
                "Type": "Pass",
                "Output": {
                    "stateInput": "{% $states.input %}",
                    "bv": "{% $bv %}",
                    "nv": "{% $nv %}",
                    "av": "{% $av %}",
                },
                "Next": "Echo",
            },
            "Echo": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Arguments": {"FunctionName": fn_arn, "Payload": {"input": "{% $states.input %}"}},
                "Output": "{% $states.result.Payload %}",
                "End": True,
            },
        },
    }

    sfn = ctx.client("stepfunctions")
    validated = sfn.validate_state_machine_definition(
        definition=json.dumps(definition), type="STANDARD"
    )
    assert (validated["result"], validated["diagnostics"]) == ("OK", []), (
        f"boolean/null/array JSONata values must validate cleanly, got {validated!r}"
    )

    sm_arn = _create_state_machine(ctx, definition, role_arn)
    exe = _run_to_terminal(ctx, sm_arn, {}, timeout_s=90)
    assert exe["status"] == "SUCCEEDED", (
        f"execution {exe['status']!r}: error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    output = json.loads(exe["output"])
    expected = {"input": {"stateInput": {}, "bv": True, "nv": None, "av": [1, "two", 3.5]}}
    assert output == expected, (
        f"expected {expected!r} to survive Assign/Output/Arguments, got {output!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
