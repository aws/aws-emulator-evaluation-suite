"""xray-segment-tree-reflects-choice-path-lambda-status-and-retry-attempts."""
from __future__ import annotations

import io
import os
import re
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xray-segment-tree-reflects-choice-path-lambda-status-and-retry-attempts"
GROUP = "observability"
SERVICES = ["stepfunctions", "xray", "lambda"]

# A sampled trace's completed segments arrive within seconds; a trace whose completed copy of
# one segment has not arrived well past that is never completed, so a fresh execution replaces it.
_XRAY_DEADLINE_S = 90.0
_TRACE_ATTEMPTS = 3
_XRAY_INTERVAL_S = 2.0
_WANT = {
    "Route": 0, "InvokeOk": 1, "InvokeMissing": 1, "InvokeRetry": 2, "InvokeBoom": 1,
    "Recovered": 0,
}
_SAMPLE_RETRY_S = 1.1
_SAMPLE_DEADLINE_S = 60.0

_HANDLER_SRC = (
    "def handler(event, context):\n"
    "    mode = event.get('mode')\n"
    "    if mode == 'retry':\n"
    "        if int(event.get('retryCount', 0)) < 1:\n"
    "            raise Exception('RetryMe')\n"
    "        return {'attempt': event.get('retryCount')}\n"
    "    if mode == 'boom':\n"
    "        raise Exception('BoomHandled')\n"
    "    return {'ok': True}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """tracingConfiguration's X-Ray segment tree carries one subsegment per visited state only
    (an untaken Choice branch is absent), a Lambda subsegment per Task with its HTTP status and
    fault/error flag, and one Lambda subsegment per Retry attempt.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")
    xray = ctx.client("xray")

    missing_fn_arn_suffix = "-sim2real-missing"

    fn_role = _create_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                        "logs:PutLogEvents"], "Resource": "*"}])
    fn_name, fn_arn = _create_function(ctx, lam, _HANDLER_SRC, fn_role)
    missing_fn_arn = fn_arn + missing_fn_arn_suffix

    sm_role = _create_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction",
         "Resource": [fn_arn, missing_fn_arn]},
        {"Effect": "Allow", "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords",
                                        "xray:GetSamplingRules", "xray:GetSamplingTargets"],
         "Resource": "*"},
    ])
    sm_name, sm_arn = _create_state_machine(ctx, sfn, _definition(fn_arn), sm_role)

    # Each state's subsegment, and the Lambda subsegments the asserts below read under it,
    # from the first execution whose trace arrives completed.
    tree = None
    for attempt in range(1, _TRACE_ATTEMPTS + 1):
        desc = _run_past_role_propagation(ctx, sfn, sm_arn, {"take": "go"})
        _assert_execution(sfn, desc)
        tree = _await_full_tree(ctx, xray, _trace_root(desc), _WANT,
                                last_attempt=attempt == _TRACE_ATTEMPTS)
        if tree is not None:
            break
    root, children = tree

    assert root["name"] == sm_name, (
        f"the trace's root segment must be named after the state machine {sm_name!r}; got "
        f"{root['name']!r}"
    )
    assert root["origin"] == "AWS::StepFunctions::StateMachine", (
        f"the root segment's origin must be 'AWS::StepFunctions::StateMachine'; got "
        f"{root.get('origin')!r}"
    )
    assert "SkipBranch" not in children, (
        "the Choice state's untaken branch 'SkipBranch' must carry no subsegment of its own; "
        f"the ingested state names were {sorted(children)}"
    )

    # --- InvokeOk: one successful Lambda subsegment, HTTP 200, no fault or error -------------
    ok_lambdas = _lambda_children(children["InvokeOk"])
    assert len(ok_lambdas) == 1, (
        f"InvokeOk must carry exactly one nested Lambda subsegment; got {len(ok_lambdas)}"
    )
    assert ok_lambdas[0]["http"]["response"]["status"] == 200, (
        f"InvokeOk's Lambda subsegment must carry HTTP response status 200; got "
        f"{ok_lambdas[0]['http']['response']}"
    )
    assert not ok_lambdas[0].get("fault") and not ok_lambdas[0].get("error"), (
        f"InvokeOk's successful Lambda subsegment must carry no fault/error flag; got "
        f"fault={ok_lambdas[0].get('fault')!r} error={ok_lambdas[0].get('error')!r}"
    )

    # --- InvokeMissing: Task-level error (E, caught), nested Lambda fault at HTTP 404 ---------
    missing_state = children["InvokeMissing"]
    assert missing_state.get("error") is True, (
        f"InvokeMissing's Catch-recovered task failure must mark the state subsegment error=True "
        f"(E); got {missing_state.get('error')!r}"
    )
    assert missing_state["cause"]["message"] == "Lambda.ResourceNotFoundException", (
        "InvokeMissing's state-level cause must name the classified error "
        f"'Lambda.ResourceNotFoundException'; got {missing_state['cause'].get('message')!r}"
    )
    missing_lambdas = _lambda_children(missing_state)
    assert len(missing_lambdas) == 1, (
        f"InvokeMissing must carry exactly one nested Lambda subsegment; got {len(missing_lambdas)}"
    )
    missing_lambda = missing_lambdas[0]
    assert missing_lambda["http"]["response"]["status"] == 404, (
        f"the Lambda subsegment for a nonexistent function must carry HTTP response status 404; "
        f"got {missing_lambda['http']['response']}"
    )
    assert missing_lambda.get("error") is True and not missing_lambda.get("fault"), (
        "a 404 ResourceNotFoundException on the Lambda invoke call must mark the subsegment "
        f"error=True (not fault); got error={missing_lambda.get('error')!r} "
        f"fault={missing_lambda.get('fault')!r}"
    )
    assert missing_lambda["aws"]["function_name"] == missing_fn_arn, (
        f"the 404 Lambda subsegment must name the function it tried to invoke, {missing_fn_arn!r}; "
        f"got {missing_lambda['aws'].get('function_name')!r}"
    )
    missing_cause_message = missing_lambda["cause"]["message"]
    # Lambda's not-found text embeds a per-call request id and the client's attempt count.
    masked_missing_cause = re.sub(
        r"Request ID: [^;)]+", "Request ID: <request-id>", missing_cause_message)
    masked_missing_cause = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", masked_missing_cause)
    expected_missing_cause = (
        f"Function not found: {missing_fn_arn}:$LATEST (Service: Lambda, Status Code: 404, "
        f"Request ID: <request-id>) (SDK Attempt Count: <n>)"
    )
    assert masked_missing_cause == expected_missing_cause, (
        f"the 404 Lambda subsegment's cause must be {expected_missing_cause!r}; got "
        f"{missing_cause_message!r}"
    )

    # --- InvokeRetry: one Lambda subsegment per attempt, fault then success -------------------
    retry_lambdas = sorted(_lambda_children(children["InvokeRetry"]), key=lambda s: s["start_time"])
    assert len(retry_lambdas) == 2, (
        f"a Task retried once (MaxAttempts=1, 1 initial + 1 retry) must carry exactly 2 nested "
        f"Lambda subsegments, one per attempt; got {len(retry_lambdas)}"
    )
    first_attempt, second_attempt = retry_lambdas
    assert first_attempt.get("fault") is True and first_attempt["aws"].get("function_error") == "Unhandled", (
        f"the first (failing) retry attempt's Lambda subsegment must carry fault=True and "
        f"aws.function_error='Unhandled'; got fault={first_attempt.get('fault')!r} "
        f"function_error={first_attempt['aws'].get('function_error')!r}"
    )
    assert first_attempt["http"]["response"]["status"] == 200, (
        "the failing retry attempt's Lambda invoke call itself still returns HTTP 200 (the "
        f"function's own exception, not the call, is what fails); got "
        f"{first_attempt['http']['response']}"
    )
    assert not second_attempt.get("fault") and not second_attempt.get("error"), (
        f"the second (succeeding) retry attempt's Lambda subsegment must carry no fault/error "
        f"flag; got fault={second_attempt.get('fault')!r} error={second_attempt.get('error')!r}"
    )
    assert second_attempt["http"]["response"]["status"] == 200, (
        f"the succeeding retry attempt must carry HTTP response status 200; got "
        f"{second_attempt['http']['response']}"
    )

    # --- InvokeBoom: Task-level error (E, caught), nested Lambda fault (F) --------------------
    boom_state = children["InvokeBoom"]
    assert boom_state.get("error") is True, (
        f"InvokeBoom's Catch-recovered task failure must mark the state subsegment error=True "
        f"(E); got {boom_state.get('error')!r}"
    )
    assert boom_state["cause"]["message"] == "Exception", (
        f"InvokeBoom's state-level cause must name the handler's exception class 'Exception'; "
        f"got {boom_state['cause'].get('message')!r}"
    )
    boom_lambdas = _lambda_children(boom_state)
    assert len(boom_lambdas) == 1, (
        f"InvokeBoom must carry exactly one nested Lambda subsegment; got {len(boom_lambdas)}"
    )
    boom_lambda = boom_lambdas[0]
    assert boom_lambda.get("fault") is True and boom_lambda["aws"].get("function_error") == "Unhandled", (
        f"a handler exception's Lambda subsegment must carry fault=True (F) and "
        f"aws.function_error='Unhandled'; got fault={boom_lambda.get('fault')!r} "
        f"function_error={boom_lambda['aws'].get('function_error')!r}"
    )
    assert boom_lambda["http"]["response"]["status"] == 200, (
        f"the Lambda invoke call for a handler exception still returns HTTP 200; got "
        f"{boom_lambda['http']['response']}"
    )


def _assert_execution(sfn, desc: dict) -> None:
    """The execution succeeded through the Catch paths with the expected Lambda outcomes."""
    assert desc["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED, got {desc['status']!r} error={desc.get('error')!r} "
        f"cause={desc.get('cause')!r}"
    )
    event_types = [e["type"] for e in _history(sfn, desc["executionArn"])]
    assert event_types.count("LambdaFunctionSucceeded") == 2, (
        "exactly 2 Lambda invocations must succeed (InvokeOk's one call, InvokeRetry's second "
        f"attempt); GetExecutionHistory showed {event_types.count('LambdaFunctionSucceeded')} "
        f"in {event_types}"
    )
    assert event_types.count("LambdaFunctionFailed") == 3, (
        "exactly 3 Lambda invocations must fail (InvokeMissing's call, InvokeRetry's first "
        f"attempt, InvokeBoom's call); GetExecutionHistory showed "
        f"{event_types.count('LambdaFunctionFailed')} in {event_types}"
    )


def _definition(fn_arn: str) -> str:
    return json.dumps({
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.take", "StringEquals": "skip", "Next": "SkipBranch"}],
                "Default": "InvokeOk",
            },
            "SkipBranch": {"Type": "Pass", "Result": "never", "End": True},
            "InvokeOk": {
                "Type": "Task",
                "Resource": fn_arn,
                "Parameters": {"mode": "ok"},
                "Next": "InvokeMissing",
            },
            "InvokeMissing": {
                "Type": "Task",
                "Resource": fn_arn + "-sim2real-missing",
                "Parameters": {"mode": "ok"},
                "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "InvokeRetry"}],
                "Next": "InvokeRetry",
            },
            "InvokeRetry": {
                "Type": "Task",
                "Resource": fn_arn,
                "Parameters": {"mode": "retry", "retryCount.$": "$$.State.RetryCount"},
                "Retry": [{
                    "ErrorEquals": ["States.ALL"],
                    "IntervalSeconds": 1,
                    "MaxAttempts": 1,
                    "BackoffRate": 1,
                }],
                "Next": "InvokeBoom",
            },
            "InvokeBoom": {
                "Type": "Task",
                "Resource": fn_arn,
                "Parameters": {"mode": "boom"},
                "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "Recovered"}],
                "End": True,
            },
            "Recovered": {"Type": "Pass", "Result": "recovered", "End": True},
        },
    })


def _zip_handler(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


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


def _create_function(ctx, lam, src, role_arn):
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + _FN_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="handler.handler", Code={"ZipFile": _zip_handler(src)},
                Timeout=10, MemorySize=128, Tags={"sim2real": CHECK},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc.response["Error"]
            time.sleep(5.0)
            continue
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


_SM_CREATE_TIMEOUT_S = 120


def _create_state_machine(ctx, sfn, definition, role_arn):
    name = ctx.unique_name("sim2real-behav-sfnxray-")
    deadline = time.monotonic() + _SM_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tracingConfiguration={"enabled": True},
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
        return name, arn
    raise AssertionError(
        f"CreateStateMachine still AccessDenied {_SM_CREATE_TIMEOUT_S}s after role creation; "
        f"last error {last!r}"
    )


def _start(ctx, sfn, sm_arn: str, payload: dict) -> str:
    """Start an execution that X-Ray samples. It passes its own traceHeader with Sampled=1; an
    execution whose recorded traceHeader still says it is unsampled is never traced, so it is
    stopped and replaced after the sampler's one-second reservoir window."""
    deadline = time.monotonic() + _SAMPLE_DEADLINE_S
    while True:
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps(payload),
            traceHeader=f"Root={_new_trace_id()};Sampled=1",
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _stop_quiet(sfn, a))
        header = sfn.describe_execution(executionArn=exec_arn).get("traceHeader") or ""
        if _trace_fields(header).get("Sampled", "1") == "1":
            return exec_arn
        _stop_quiet(sfn, exec_arn)
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no execution of {sm_arn} was sampled for X-Ray within {_SAMPLE_DEADLINE_S}s; "
                f"the last traceHeader was {header!r}"
            )
        time.sleep(_SAMPLE_RETRY_S)


def _new_trace_id() -> str:
    return f"1-{int(time.time()):08x}-{os.urandom(12).hex()}"


def _trace_fields(header: str) -> dict:
    return dict(p.split("=", 1) for p in header.split(";") if "=" in p)


def _stop_quiet(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


_ROLE_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "is not authorized to perform: lambda:InvokeFunction",
)
_ROLE_PROPAGATION_TIMEOUT_S = 120


def _run_past_role_propagation(ctx, sfn, sm_arn: str, payload: dict) -> dict:
    """Start an execution, bounded-retrying a whole new execution only while the state machine's
    freshly created role, its trust or its invoke grant, is still propagating."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        exec_arn = _start(ctx, sfn, sm_arn, payload)
        last = _wait_terminal(ctx, sfn, exec_arn, timeout_s=180.0)
        cause = last.get("cause") or ""
        if not any(marker in cause for marker in _ROLE_PROPAGATION_MARKERS):
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"execution still hitting role-trust propagation {_ROLE_PROPAGATION_TIMEOUT_S}s after "
        f"role creation; last: {last!r}"
    )


def _wait_terminal(ctx, sfn, exec_arn: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s: {last!r}")


def _history(sfn, exec_arn: str) -> list[dict]:
    events: list[dict] = []
    kwargs = {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return events
        kwargs["nextToken"] = token


def _trace_root(desc: dict) -> str:
    """The X-Ray trace id of the execution DescribeExecution describes, from its traceHeader."""
    header = desc.get("traceHeader") or ""
    fields = _trace_fields(header)
    assert fields.get("Root"), (
        f"a traced execution's DescribeExecution must carry a traceHeader with a Root; got "
        f"{header!r}"
    )
    return fields["Root"]


def _lambda_children(state_segment: dict) -> list[dict]:
    return [s for s in state_segment.get("subsegments", []) if s.get("namespace") == "aws"]


def _trace_documents(xray, trace_id: str) -> list[dict]:
    """Every segment document BatchGetTraces holds for one trace id, across all pages."""
    docs, kwargs = [], {"TraceIds": [trace_id]}
    while True:
        resp = xray.batch_get_traces(**kwargs)
        for trace in resp["Traces"]:
            if trace.get("Id") == trace_id:
                docs.extend(json.loads(s["Document"]) for s in trace.get("Segments", []))
        if not resp.get("NextToken"):
            return docs
        kwargs["NextToken"] = resp["NextToken"]


def _root_and_state_children(docs: list[dict], trace_id: str) -> tuple[dict, dict]:
    """The execution's root segment (origin AWS::StepFunctions::StateMachine) plus its direct
    children keyed by ASL state name. X-Ray also returns separate 'inferred' Lambda segments
    alongside the root in the same BatchGetTraces response; those are not state children."""
    roots = [d for d in docs if d.get("origin") == "AWS::StepFunctions::StateMachine"]
    if not roots:
        return {}, {}
    assert len(roots) == 1, (
        f"trace {trace_id!r} must carry exactly one AWS::StepFunctions::StateMachine root "
        f"segment; got {len(roots)} among origins {[d.get('origin') for d in docs]}"
    )
    root = roots[0]
    children = {s["name"]: s for s in root.get("subsegments", [])}
    return root, children


def _closed(segment: dict) -> bool:
    """Whether a segment or subsegment arrived in its completed form, flags and cause set."""
    return "end_time" in segment and not segment.get("in_progress")


def _incomplete(root: dict, children: dict, want: dict) -> list[str]:
    """The parts of the tree not yet arrived completed: the root segment, a wanted state
    subsegment, or a state short of its wanted number of completed Lambda subsegments."""
    if not root:
        return ["root segment absent"]
    parts = [] if _closed(root) else ["root segment in progress"]
    for state, n_lambdas in want.items():
        if state not in children:
            parts.append(f"{state} absent")
            continue
        if not _closed(children[state]):
            parts.append(f"{state} in progress")
        closed = sum(_closed(s) for s in _lambda_children(children[state]))
        if closed < n_lambdas:
            parts.append(f"{state} has {closed}/{n_lambdas} completed Lambda subsegments")
    return parts


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_full_tree(ctx, xray, trace_id: str, want: dict, *,
                     last_attempt: bool) -> tuple[dict, dict] | None:
    """X-Ray ingestion is incremental: a trace can resolve with only its earliest subsegments
    present, or with one still in progress. Poll BatchGetTraces until the Step Functions root
    segment, every wanted state subsegment and the Lambda subsegments nested under each have
    arrived completed; None when they have not within the wait and another execution may
    replace this one."""
    timeout_s = _budget_s(ctx, _XRAY_DEADLINE_S)
    deadline = time.monotonic() + timeout_s
    root, children, origins, missing = {}, {}, [], []
    while True:
        docs = _trace_documents(xray, trace_id)
        origins = [d.get("origin") for d in docs]
        root, children = _root_and_state_children(docs, trace_id)
        missing = _incomplete(root, children, want)
        if not missing:
            return root, children
        if time.monotonic() >= deadline:
            break
        time.sleep(_XRAY_INTERVAL_S)
    if not last_attempt and not _budget_spent(ctx):
        return None
    seen = (f"incomplete {missing}; last seen states {sorted(children)} among segment origins "
            f"{origins}; Lambda subsegments per state "
            f"{ {name: len(_lambda_children(seg)) for name, seg in children.items()} }")
    if _budget_spent(ctx):
        raise TimeoutError(
            f"trace {trace_id!r} had not ingested all of {want!r} when the run budget ended; "
            f"{seen}; not graded"
        )
    raise AssertionError(
        f"the trace of each of {_TRACE_ATTEMPTS} executions stayed incomplete; the last, "
        f"{trace_id!r}, never ingested completed subsegments for all of {want!r} within "
        f"{timeout_s:.0f}s; {seen}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
