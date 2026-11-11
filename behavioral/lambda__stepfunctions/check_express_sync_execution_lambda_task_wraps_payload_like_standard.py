"""express-sync-execution-lambda-task-wraps-payload-like-standard."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "express-sync-execution-lambda-task-wraps-payload-like-standard"
GROUP = "express_workflows"
SERVICES = ["lambda", "stepfunctions"]

_HANDLER_SRC = (
    "def handler(event, context):\n"
    "    return {'echo': event}\n"
)


@tags("axis:happy-path", "cap:c3", "concern:representation", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSyncExecution on an EXPRESS machine wraps a successful lambda:invoke Task's output in
    an envelope carrying ExecutedVersion, Payload and StatusCode, as a STANDARD execution's
    DescribeExecution does, plus billingDetails that STANDARD never carries.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role = _lambda_role(ctx, iam)
    fn_name, fn_arn = _create_function(ctx, lam, _HANDLER_SRC, fn_role)
    sm_role = _make_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])
    definition = _definition(fn_arn)

    standard_sm = _create_state_machine(ctx, sfn, definition, sm_role, "STANDARD")
    standard = _await_role_assumable_standard(sfn, standard_sm)
    assert standard["status"] == "SUCCEEDED", (
        f"the STANDARD control execution must succeed, got {standard['status']!r}"
    )
    standard_output = json.loads(standard["output"])
    assert set(standard_output) >= {"ExecutedVersion", "Payload", "StatusCode"}, (
        f"STANDARD's DescribeExecution output must wrap the invoke; got {standard_output!r}"
    )
    assert standard_output["Payload"] == {"echo": {"probe": "standard"}}, (
        f"the wrapped Payload must carry the handler's own return value; got "
        f"{standard_output['Payload']!r}"
    )
    assert "billingDetails" not in standard, (
        f"STANDARD's DescribeExecution must carry no billingDetails; got {standard.get('billingDetails')!r}"
    )

    express_sm = _create_state_machine(ctx, sfn, definition, sm_role, "EXPRESS")
    express = _await_role_assumable_sync(sfn, express_sm)
    assert express["status"] == "SUCCEEDED", (
        f"the EXPRESS sync execution must succeed, got {express['status']!r}, cause "
        f"{express.get('cause')!r}"
    )
    express_output = json.loads(express["output"])
    assert set(express_output) >= {"ExecutedVersion", "Payload", "StatusCode"}, (
        f"StartSyncExecution's output must carry the ExecutedVersion/Payload/StatusCode envelope "
        f"STANDARD's does; got "
        f"{express_output!r}"
    )
    assert express_output["Payload"] == {"echo": {"probe": "express"}}, (
        f"the wrapped Payload must carry the handler's own return value; got "
        f"{express_output['Payload']!r}"
    )
    assert express_output["ExecutedVersion"] == standard_output["ExecutedVersion"], (
        f"both targets invoke the same unqualified function, so ExecutedVersion must agree: "
        f"STANDARD {standard_output['ExecutedVersion']!r} vs EXPRESS {express_output['ExecutedVersion']!r}"
    )
    billing = express.get("billingDetails")
    assert isinstance(billing, dict) and {"billedMemoryUsedInMB", "billedDurationInMilliseconds"} <= set(billing), (
        f"StartSyncExecution must report billingDetails, which DescribeExecution never carries; "
        f"got {billing!r}"
    )


def _definition(fn_arn: str) -> str:
    """A single lambda:invoke Task, no Retry or Catch."""
    return json.dumps({
        "StartAt": "Invoke",
        "States": {"Invoke": {
            "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
            "End": True,
        }},
    })


_TAGS = {"sim2real:managed": "true", "sim2real": CHECK[:200]}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_SFN_TAGLIST = [{"key": k, "value": v} for k, v in _TAGS.items()]
_FN_CREATE_TIMEOUT_S = 240
_TRUST_BARRIER_TIMEOUT_S = 240


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


def _create_state_machine(ctx, sfn, definition, role_arn, sm_type):
    name = ctx.unique_name(f"sim2real-scn-sm-{sm_type.lower()}-")
    arn = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn,
                                   type=sm_type, tags=_SFN_TAGLIST)["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                             "StateMachineDoesNotExist"))
    return arn


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _is_propagation_lag(cause: str) -> bool:
    """True when ``cause`` names a fresh role's credentials not yet usable, not a real failure."""
    return any(marker in cause for marker in (
        "not authorized to assume",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "security token included in the request is invalid",
    ))


def _await_role_assumable_standard(sfn, sm_arn):
    """Poll DescribeExecution to a terminal status, retrying while role trust has not propagated."""
    deadline = time.monotonic() + _TRUST_BARRIER_TIMEOUT_S
    last = {}
    while time.monotonic() < deadline:
        ex = sfn.start_execution(
            stateMachineArn=sm_arn, name="sim2real-x-" + uuid.uuid4().hex[:12],
            input=json.dumps({"probe": "standard"}),
        )["executionArn"]
        last = _poll_until(lambda: sfn.describe_execution(executionArn=ex),
                           lambda d: d["status"] != "RUNNING",
                           description=f"execution {ex} reached a terminal status")
        if last["status"] != "FAILED" or not _is_propagation_lag(last.get("cause") or ""):
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"the STANDARD execution never left the role-trust race within {_TRUST_BARRIER_TIMEOUT_S}s: "
        f"last status {last.get('status')!r}, cause {(last.get('cause') or '')[:300]!r}"
    )


def _await_role_assumable_sync(sfn, sm_arn):
    """Call StartSyncExecution until it leaves the role-trust-propagation race, win or lose."""
    deadline = time.monotonic() + _TRUST_BARRIER_TIMEOUT_S
    last = {}
    while time.monotonic() < deadline:
        last = sfn.start_sync_execution(
            stateMachineArn=sm_arn, name="sim2real-x-" + uuid.uuid4().hex[:12],
            input=json.dumps({"probe": "express"}),
        )
        if last["status"] != "FAILED" or not _is_propagation_lag(last.get("cause") or ""):
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"the EXPRESS sync execution never left the role-trust race within "
        f"{_TRUST_BARRIER_TIMEOUT_S}s: last status {last.get('status')!r}, cause "
        f"{(last.get('cause') or '')[:300]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
