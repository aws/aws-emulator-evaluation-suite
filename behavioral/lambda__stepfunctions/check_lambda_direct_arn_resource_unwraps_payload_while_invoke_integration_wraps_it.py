"""lambda-direct-arn-resource-unwraps-payload-while-invoke-integration-wraps-it."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-direct-arn-resource-unwraps-payload-while-invoke-integration-wraps-it"
GROUP = "execution-output"
SERVICES = ["lambda", "stepfunctions"]


def _src(label: str) -> str:
    """A handler returning its code label beside the event, so the caller can tell which ran."""
    return (
        "def handler(event, context):\n"
        f"    return {{'code': {label!r}, 'echo': event}}\n"
    )


@tags("axis:happy-path", "cap:c3", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Task whose Resource names a Lambda ARN directly returns its raw payload unwrapped and
    honors a version/alias/$LATEST qualifier appended to that ARN, while arn:aws:states:::
    lambda:invoke wraps the identical qualified call in ExecutedVersion/Payload/StatusCode.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role = _lambda_role(ctx, iam)
    name, fn_arn = _create_function(ctx, lam, _src("one"), fn_role)
    v1 = lam.publish_version(FunctionName=name)["Version"]
    alias_arn = lam.create_alias(FunctionName=name, Name="live", FunctionVersion=v1)["AliasArn"]

    lam.update_function_code(FunctionName=name, ZipFile=_zip_handler(_src("two")))
    lam.get_waiter("function_updated_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    v2 = lam.publish_version(FunctionName=name)["Version"]
    assert v1 != v2, f"two publishes of different code must mint two versions, got {v1!r} twice"

    lam.update_function_code(FunctionName=name, ZipFile=_zip_handler(_src("latest")))
    lam.get_waiter("function_updated_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    sm_role = _make_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction",
         "Resource": [fn_arn, f"{fn_arn}:*"]}])
    definition = json.dumps({
        "StartAt": "Compare",
        "States": {"Compare": {
            "Type": "Parallel", "End": True,
            "Branches": [
                {"StartAt": "DirectUnqualified", "States": {"DirectUnqualified": {
                    "Type": "Task", "Resource": fn_arn, "End": True}}},
                {"StartAt": "DirectVersion", "States": {"DirectVersion": {
                    "Type": "Task", "Resource": f"{fn_arn}:{v1}", "End": True}}},
                {"StartAt": "DirectAlias", "States": {"DirectAlias": {
                    "Type": "Task", "Resource": alias_arn, "End": True}}},
                {"StartAt": "OptimizedVersion", "States": {"OptimizedVersion": {
                    "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {"FunctionName": f"{fn_arn}:{v2}", "Payload.$": "$"},
                    "End": True}}},
            ],
        }},
    })
    _, sm = _create_state_machine(ctx, sfn, definition, sm_role)

    done = _await_role_assumable(sfn, sm)
    assert done["status"] == "SUCCEEDED", (
        f"the comparison execution must succeed, got {done['status']!r} error={done.get('error')!r} "
        f"cause={(done.get('cause') or '')[:300]!r}"
    )
    branches = json.loads(done["output"])
    assert len(branches) == 4, f"the Parallel must report one output per branch, got {len(branches)}"
    direct_unqualified, direct_version, direct_alias, optimized_version = branches

    assert direct_unqualified == {"code": "latest", "echo": {"executionType": "scheduled"}}, (
        f"an unqualified direct ARN Resource must invoke $LATEST and return its raw payload "
        f"unwrapped; got {direct_unqualified!r}"
    )
    assert direct_version == {"code": "one", "echo": {"executionType": "scheduled"}}, (
        f"a direct ARN Resource qualified with version {v1!r} must return that version's raw "
        f"payload unwrapped; got {direct_version!r}"
    )
    assert direct_alias == {"code": "one", "echo": {"executionType": "scheduled"}}, (
        f"a direct ARN Resource qualified with the 'live' alias (-> version {v1!r}) must return "
        f"that version's raw payload unwrapped; got {direct_alias!r}"
    )
    assert isinstance(optimized_version, dict) and set(optimized_version) >= {
        "ExecutedVersion", "Payload", "StatusCode", "SdkHttpMetadata"}, (
        f"arn:aws:states:::lambda:invoke must wrap its response in ExecutedVersion/Payload/"
        f"StatusCode/SdkHttpMetadata even for a qualified FunctionName; got {optimized_version!r}"
    )
    assert optimized_version["ExecutedVersion"] == v2, (
        f"the optimized integration's ExecutedVersion must name the qualified version {v2!r} "
        f"invoked; got {optimized_version['ExecutedVersion']!r}"
    )
    assert optimized_version["Payload"] == {"code": "two", "echo": {"executionType": "scheduled"}}, (
        f"the optimized integration must still carry the function's own return value under "
        f"Payload; got {optimized_version['Payload']!r}"
    )
    assert optimized_version["StatusCode"] == 200, (
        f"a successful optimized invoke reports StatusCode 200; got {optimized_version['StatusCode']!r}"
    )


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


def _create_function(ctx, lam, src, role_arn, **extra):
    """Create an inline-source function, retrying while a fresh role is not yet assumable."""
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


def _run_to_terminal(sfn, sm_arn, *, payload='{"executionType": "scheduled"}'):
    """Start one execution and poll it to a terminal status."""
    ex = sfn.start_execution(
        stateMachineArn=sm_arn,
        name="sim2real-x-" + uuid.uuid4().hex[:12],
        input=payload,
    )["executionArn"]
    return _poll_until(lambda: sfn.describe_execution(executionArn=ex),
                       lambda d: d["status"] != "RUNNING",
                       description=f"execution {ex} reached a terminal status")


# Failures of the fresh execution role's trust, token or invoke grant not yet propagated.
_PROPAGATION_NEEDLES = ("not authorized to assume", "UnrecognizedClientException", "AccessDeniedException")


def _await_role_assumable(sfn, control_sm_arn, *, payload='{"executionType": "scheduled"}'):
    """Run executions until one ends other than in an IAM propagation failure and return it: a
    new role and its grant are not usable by Step Functions at once."""
    deadline = time.monotonic() + _TRUST_BARRIER_TIMEOUT_S
    last = {}
    while time.monotonic() < deadline:
        last = _run_to_terminal(sfn, control_sm_arn, payload=payload)
        cause = last.get("cause") or ""
        if last["status"] != "FAILED" or not any(n in cause for n in _PROPAGATION_NEEDLES):
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"executions still failed on IAM propagation after {_TRUST_BARRIER_TIMEOUT_S}s: "
        f"last status {last.get('status')!r}, cause {(last.get('cause') or '')[:300]!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
