"""express-sync-execution-retry-and-catch-match-standards-shapes."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "express-sync-execution-retry-and-catch-match-standards-shapes"
GROUP = "express_workflows"
SERVICES = ["lambda", "stepfunctions"]

_HANDLER_SRC = (
    "def handler(event, context):\n"
    "    if event.get('fail'):\n"
    "        raise Exception('sim2real: this handler always raises')\n"
    "    return {'ok': True}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSyncExecution reports a Task's Retry and Catch outcome inline: a caught failure comes
    back SUCCEEDED with the same {Error, Cause} shape STANDARD's Catch produces, and an uncaught
    one comes back FAILED with the handler's own error and cause at the top level.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role = _lambda_role(ctx, iam)
    fn_name, fn_arn = _create_function(ctx, lam, _HANDLER_SRC, fn_role)
    sm_role = _make_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])

    caught_sm = _create_state_machine(ctx, sfn, _definition(fn_arn, caught=True), sm_role)

    # Positive control: nothing fails, the Catch branch is never entered.
    ok = _sync_until_settled(sfn, caught_sm, json.dumps({"fail": False}), is_settled=_ok_settled)
    assert ok["status"] == "SUCCEEDED", f"the happy path must succeed, got {ok['status']!r}"
    ok_output = json.loads(ok["output"])
    assert ok_output["Payload"] == {"ok": True}, (
        f"an uncaught success must still carry the handler's return value; got {ok_output!r}"
    )

    # Negative A: the Task retries once, still raises, and the Catch converts it to SUCCEEDED.
    caught = _sync_until_settled(sfn, caught_sm, json.dumps({"fail": True}), is_settled=_caught_settled)
    assert caught["status"] == "SUCCEEDED", (
        f"a Catch-ErrorEquals-States.ALL branch must turn the failure into SUCCEEDED; got "
        f"{caught['status']!r}"
    )
    caught_output = json.loads(caught["output"])
    assert set(caught_output) == {"Error", "Cause"}, (
        f"the default Catch output is exactly Error+Cause; got keys {set(caught_output)}"
    )
    assert caught_output["Error"] == "Exception", (
        f"the caught Error must name the handler's own exception class; got {caught_output['Error']!r}"
    )
    caught_cause = json.loads(caught_output["Cause"])
    assert caught_cause["errorMessage"] == "sim2real: this handler always raises", (
        f"the caught Cause must carry the handler's own message; got {caught_cause!r}"
    )

    # Negative B: the identical Task with no Catch leaves the sync response itself FAILED.
    uncaught_sm = _create_state_machine(ctx, sfn, _definition(fn_arn, caught=False), sm_role)
    uncaught = _sync_until_settled(
        sfn, uncaught_sm, json.dumps({"fail": True}), is_settled=_uncaught_settled)
    assert uncaught["status"] == "FAILED", (
        f"with no Catch, retries exhaust and the sync response itself must be FAILED; got "
        f"{uncaught['status']!r}"
    )
    assert uncaught.get("error") == "Exception", (
        f"StartSyncExecution must surface the handler's exception class at the top level with "
        f"no polling; got {uncaught.get('error')!r}"
    )
    uncaught_cause = json.loads(uncaught["cause"])
    assert uncaught_cause["errorMessage"] == "sim2real: this handler always raises", (
        f"the top-level cause must carry the handler's own message; got {uncaught_cause!r}"
    )
    assert "output" not in uncaught, (
        f"a FAILED sync execution must carry no output; got {uncaught.get('output')!r}"
    )


def _definition(fn_arn: str, *, caught: bool) -> str:
    """One retried lambda:invoke Task, optionally caught into a Pass that ends the machine."""
    task: dict = {
        "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
        "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
        "Retry": [{"ErrorEquals": ["States.ALL"], "IntervalSeconds": 1, "MaxAttempts": 1,
                   "BackoffRate": 2.0}],
    }
    states = {}
    if caught:
        task["Catch"] = [{"ErrorEquals": ["States.ALL"], "Next": "Caught"}]
        task["Next"] = "Succeed"
        states["Succeed"] = {"Type": "Succeed"}
        states["Caught"] = {"Type": "Pass", "End": True}
    else:
        task["End"] = True
    states["Invoke"] = task
    return json.dumps({"StartAt": "Invoke", "States": states})


_TAGS = {"sim2real:managed": "true", "sim2real": CHECK[:200]}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_SFN_TAGLIST = [{"key": k, "value": v} for k, v in _TAGS.items()]
_FN_CREATE_TIMEOUT_S = 240


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _zip_handler(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _make_role(ctx, iam, service, statements):
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
    return _make_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                       "logs:PutLogEvents"], "Resource": "*"}])


def _create_function(ctx, lam, src, role_arn, **extra):
    name = ctx.unique_name("sim2real-scn-fn-")
    deadline = time.monotonic() + _FN_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="handler.handler", Code={"ZipFile": _zip_handler(src)},
                Timeout=20, MemorySize=128, Tags=_TAGS, **extra,
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc.response["Error"]
            time.sleep(5.0)
            continue
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
    name = ctx.unique_name("sim2real-scn-sm-")
    arn = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn,
                                   type="EXPRESS", tags=_SFN_TAGLIST)["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                             "StateMachineDoesNotExist"))
    return arn


def _is_propagation_lag(cause: str) -> bool:
    """True when ``cause`` names a fresh role's credentials not yet usable, not a real failure."""
    return any(marker in cause for marker in (
        "not authorized to assume",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "security token included in the request is invalid",
    ))


def _ok_settled(result: dict) -> bool:
    """True once the happy path shows the handler's own success, not a transient infra error."""
    if result.get("status") != "SUCCEEDED":
        return not _is_propagation_lag(result.get("cause") or "")
    output = json.loads(result["output"])
    return "Payload" in output


def _caught_settled(result: dict) -> bool:
    """True once the Catch output names the handler's own exception, not a transient one."""
    if result.get("status") != "SUCCEEDED":
        return False
    output = json.loads(result["output"])
    if set(output) != {"Error", "Cause"}:
        return False
    return not _is_propagation_lag(output.get("Cause") or "")


def _uncaught_settled(result: dict) -> bool:
    """True once the top-level error names the handler's own exception, not a transient one."""
    if result.get("status") != "FAILED":
        return False
    return result.get("error") == "Exception" or not _is_propagation_lag(result.get("cause") or "")


def _sync_until_settled(sfn, sm_arn, payload, *, is_settled, timeout_s=90.0):
    """StartSyncExecution, retried at this first use while a fresh role is not yet fully usable.

    IAM propagation can surface three ways depending on where the lag lands: the sync response
    itself FAILED on a transient cause, or the Task's Retry/Catch absorbed that same cause and
    reports a shape that isn't the handler's own outcome yet. Raises at the deadline.
    """
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = sfn.start_sync_execution(
            stateMachineArn=sm_arn, name="sim2real-x-" + uuid.uuid4().hex[:12], input=payload,
        )
        if is_settled(last):
            return last
        time.sleep(2.0)
    raise AssertionError(
        f"no sync execution settled past IAM propagation within {timeout_s}s: status "
        f"{last.get('status')!r} error={last.get('error')!r} cause={(last.get('cause') or '')[:300]!r} "
        f"output={(last.get('output') or '')[:300]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
