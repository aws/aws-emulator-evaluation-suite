"""durable-chained-invoke-of-a-never-created-function-fails."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "durable-chained-invoke-of-a-never-created-function-fails"
GROUP = "server-side"
SERVICES = ["iam", "lambda", "logs"]

_CHAIN_SOURCE = """
from aws_durable_execution_sdk_python import DurableContext, durable_execution


@durable_execution
def lambda_handler(event, context: DurableContext):
    return context.invoke(event["target_arn"], event.get("payload"))
"""

_ECHO_SOURCE = """
def handler(event, context):
    return {"echoed": event}
"""

_TERMINAL_STATUSES = ("SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A durable context.invoke() naming a function ARN that was never created ends the
    execution FAILED with an error naming that ARN, recorded as a ChainedInvokeFailed event
    and never a ChainedInvokeSucceeded one; the same chain against an existing target succeeds.
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn, role_name = _make_execution_role(ctx)

    chain_fn = ctx.unique_name("sim2real-chainmiss-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{chain_fn}"))
    _create_durable_function(ctx, lam, chain_fn, role_arn, _CHAIN_SOURCE)

    absent_fn = ctx.unique_name("sim2real-chainmiss-absent-")
    absent_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{absent_fn}"

    refused_arn, refused = _run_chain_to_terminal(lam, chain_fn, absent_arn, None)
    assert refused["Status"] == "FAILED", (
        f"a chained invoke of a function ARN that was never created should fail the execution, "
        f"got {refused['Status']!r} with error {refused.get('Error')!r}"
    )
    expected_message = f"Function not found: {absent_arn}:$LATEST"
    refused_error = refused.get("Error", {})
    assert refused_error.get("ErrorMessage") == expected_message, (
        f"expected the execution's error to name the never-created target as "
        f"{expected_message!r}, got {refused_error.get('ErrorMessage')!r}"
    )
    assert refused_error.get("ErrorType") == "CallableRuntimeError", (
        f"expected the propagated invoke error's type to be CallableRuntimeError, "
        f"got {refused_error.get('ErrorType')!r}"
    )

    refused_events = _events_by_type(lam, refused_arn)
    assert "ChainedInvokeFailed" in refused_events, (
        f"expected a ChainedInvokeFailed event for the missing target, "
        f"got {sorted(refused_events)!r}"
    )
    assert "ChainedInvokeSucceeded" not in refused_events, (
        f"a chained invoke that failed must not also carry a ChainedInvokeSucceeded event, "
        f"got {sorted(refused_events)!r}"
    )
    started_details = refused_events["ChainedInvokeStarted"]["ChainedInvokeStartedDetails"]
    assert started_details["FunctionName"] == absent_arn, (
        f"ChainedInvokeStartedDetails.FunctionName should name the requested target "
        f"{absent_arn!r}, got {started_details.get('FunctionName')!r}"
    )
    failed_payload = refused_events["ChainedInvokeFailed"]["ChainedInvokeFailedDetails"]["Error"]["Payload"]
    assert failed_payload == {"ErrorMessage": expected_message, "ErrorType": "ResourceNotFoundException"}, (
        f"ChainedInvokeFailedDetails.Error.Payload should carry the ResourceNotFoundException "
        f"that named the missing target, got {failed_payload!r}"
    )

    echo_fn = ctx.unique_name("sim2real-chainmiss-echo-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{echo_fn}"))
    echo_arn = _create_plain_function(ctx, lam, echo_fn, role_arn)

    control_payload = {"marker": "chainmiss"}
    present_arn, present = _run_chain_to_terminal(lam, chain_fn, echo_arn, control_payload)
    assert present["Status"] == "SUCCEEDED", (
        f"the identical chain pointed at a function that exists should succeed, "
        f"got {present['Status']!r} with error {present.get('Error')!r}"
    )
    expected_result = json.dumps({"echoed": control_payload})
    assert present.get("Result") == expected_result, (
        f"expected the execution's own Result to carry the target's live reply "
        f"{expected_result!r}, got {present.get('Result')!r}"
    )

    present_events = _events_by_type(lam, present_arn)
    assert "ChainedInvokeSucceeded" in present_events, (
        f"expected a ChainedInvokeSucceeded event once the target exists, "
        f"got {sorted(present_events)!r}"
    )
    assert "ChainedInvokeFailed" not in present_events, (
        f"a chain against an existing target recorded a ChainedInvokeFailed too, "
        f"got {sorted(present_events)!r}"
    )
    succeeded_result = present_events["ChainedInvokeSucceeded"]["ChainedInvokeSucceededDetails"]["Result"]
    assert succeeded_result == {"Payload": expected_result, "Truncated": False}, (
        f"ChainedInvokeSucceededDetails.Result should carry the target's untruncated reply "
        f"{expected_result!r}, got {succeeded_result!r}"
    )


# ===== deployment helpers =====


def _source_zip(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(filename, source)
    return buf.getvalue()


def _make_execution_role(ctx: Any) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-chainmiss-role-")
    trust_document = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_document),
        Tags=[{"Key": "sim2real", "Value": "chainmiss"}],
    )
    role_arn = created["Role"]["Arn"]

    durable_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=durable_policy_arn)

    def _detach_and_delete_role() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=durable_policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_detach_and_delete_role)

    # Chained invokes are made under this role's identity, so it needs lambda:InvokeFunction on
    # every function this account could ever hold; scoping to one target ARN would also deny the
    # case this check is about (a target ARN that names no function at all).
    invoke_policy_name = ctx.unique_name("sim2real-chainmiss-invoke-")
    invoke_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=invoke_policy_name,
        PolicyDocument=json.dumps(invoke_policy_document),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=invoke_policy_name))

    deadline = time.monotonic() + 30.0
    while True:
        try:
            iam.get_role_policy(RoleName=role_name, PolicyName=invoke_policy_name)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)

    return role_arn, role_name


def _create_durable_function(ctx: Any, lam, name: str, role_arn: str, source: str) -> None:
    code = {"ZipFile": _source_zip("lambda_function.py", source)}
    deadline = time.monotonic() + 90.0
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.13",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code=code,
                Timeout=60,
                MemorySize=256,
                DurableConfig={"ExecutionTimeout": 180, "RetentionPeriodInDays": 1},
            )
            break
        except ClientError as exc:
            code_name = exc.response["Error"]["Code"]
            if code_name == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_until_active(lam, name)


def _create_plain_function(ctx: Any, lam, name: str, role_arn: str) -> str:
    code = {"ZipFile": _source_zip("index.py", _ECHO_SOURCE)}
    deadline = time.monotonic() + 90.0
    while True:
        try:
            created = lam.create_function(
                FunctionName=name,
                Runtime="python3.13",
                Role=role_arn,
                Handler="index.handler",
                Code=code,
                Timeout=10,
                MemorySize=128,
            )
            break
        except ClientError as exc:
            code_name = exc.response["Error"]["Code"]
            if code_name == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_until_active(lam, name)
    return created["FunctionArn"]


def _wait_until_active(lam, name: str, timeout_s: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Active":
            return
        if last["State"] == "Failed":
            raise AssertionError(f"{name} entered state Failed: {last.get('StateReason')!r}")
        time.sleep(1.0)
    raise AssertionError(f"{name} did not reach Active within {timeout_s}s, last={last!r}")


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    The function's log group outlives DeleteFunction and late log delivery can bring it back,
    so the delete repeats until the group stays gone.
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
                raise AssertionError(f"{name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


# ===== execution helpers =====


def _run_chain_to_terminal(lam, chain_fn: str, target_arn: str, payload) -> tuple[str, dict]:
    """Start one fresh durable execution and poll it to a terminal status.

    Right after the role's invoke policy is written, the chained call can still be refused as
    not authorized for ``InvokeFunction``. Only that outcome starts another execution, up to six
    in all; every other terminal status is returned as the result.
    """
    attempt = 0
    while True:
        attempt += 1
        execution_arn = _start_execution(lam, chain_fn, target_arn, payload)
        final = _poll_to_terminal(lam, execution_arn)
        error_message = final.get("Error", {}).get("ErrorMessage", "")
        is_propagation_lag = (
            final["Status"] == "FAILED"
            and "InvokeFunction" in error_message
            and "not authorized" in error_message
        )
        if not is_propagation_lag or attempt >= 6:
            return execution_arn, final
        time.sleep(5.0)


def _start_execution(lam, function_name: str, target_arn: str, payload) -> str:
    execution_name = _execution_name(function_name)
    event = {"target_arn": target_arn, "payload": payload}
    response = lam.invoke(
        FunctionName=function_name,
        Qualifier="$LATEST",
        InvocationType="Event",
        Payload=json.dumps(event).encode("utf-8"),
        DurableExecutionName=execution_name,
    )
    arn = response.get("DurableExecutionArn")
    if arn:
        return arn
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        listing = lam.list_durable_executions_by_function(FunctionName=function_name, Qualifier="$LATEST")
        for execution in listing.get("DurableExecutions", []):
            if execution.get("DurableExecutionName") == execution_name:
                return execution["DurableExecutionArn"]
        time.sleep(2.0)
    raise AssertionError(f"no durable execution named {execution_name!r} appeared for {function_name!r}")


def _execution_name(function_name: str) -> str:
    return f"{function_name}-{time.monotonic_ns()}"


def _poll_to_terminal(lam, execution_arn: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = lam.get_durable_execution(DurableExecutionArn=execution_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
            continue
        if last["Status"] in _TERMINAL_STATUSES:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{execution_arn} did not reach a terminal status within {timeout_s}s, last={last!r}")


def _events_by_type(lam, execution_arn: str) -> dict[str, dict]:
    events = lam.get_durable_execution_history(
        DurableExecutionArn=execution_arn, IncludeExecutionData=True
    )["Events"]
    return {event["EventType"]: event for event in events}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
