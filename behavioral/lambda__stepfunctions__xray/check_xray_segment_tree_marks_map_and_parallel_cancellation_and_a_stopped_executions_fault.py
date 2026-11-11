"""xray-segment-tree-marks-map-and-parallel-cancellation-and-a-stopped-executions-fault."""
from __future__ import annotations

import io
import json
import os
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xray-segment-tree-marks-map-and-parallel-cancellation-and-a-stopped-executions-fault"
GROUP = "observability"
SERVICES = ["stepfunctions", "xray", "lambda"]

_XRAY_DEADLINE_S = 420.0
_XRAY_INTERVAL_S = 2.0
_SAMPLE_RETRY_S = 1.1
_SAMPLE_DEADLINE_S = 60.0
_SLOW_SECONDS = 20

_HANDLER_SRC = (
    "import time\n"
    "def handler(event, context):\n"
    "    mode = event.get('mode')\n"
    "    if mode == 'boomfast':\n"
    "        raise Exception('BoomFast')\n"
    "    if mode == 'slow':\n"
    "        time.sleep(%d)\n"
    "        return {'ok': True}\n"
    "    return {'ok': True}\n"
) % _SLOW_SECONDS


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A sibling's failure cancels a running Parallel branch and a running Map iteration — both
    marked error=True, cause 'Canceled' — and StopExecution faults the root segment and marks the
    running task's own subsegment error=True, cause 'Canceled'.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")
    xray = ctx.client("xray")

    fn_role = _create_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                        "logs:PutLogEvents"], "Resource": "*"}])
    fn_name, fn_arn = _create_function(ctx, lam, _HANDLER_SRC, fn_role)

    sm_role = _create_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn},
        {"Effect": "Allow", "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords",
                                        "xray:GetSamplingRules", "xray:GetSamplingTargets"],
         "Resource": "*"},
    ])
    par_sm_arn = _create_state_machine(ctx, sfn, _parallel_definition(fn_arn), sm_role)
    map_sm_arn = _create_state_machine(ctx, sfn, _map_definition(fn_arn), sm_role)
    stop_sm_arn = _create_state_machine(ctx, sfn, _stop_definition(fn_arn), sm_role)

    # --- Parallel: a sibling branch is canceled when the other one fails --------------------
    par_desc = _run_past_role_propagation(ctx, sfn, par_sm_arn, {})
    assert par_desc["status"] == "FAILED", (
        f"the Parallel state's always-failing branch must fail the execution; got "
        f"{par_desc['status']!r}"
    )
    _, par_children = _await_full_tree(
        ctx, xray, _trace_root(par_desc),
        {"RunParallel": {"Branch 0": "FastBoom", "Branch 1": "SlowOk"}})
    par_branches = par_children["RunParallel"].get("subsegments", [])
    par_by_name = {b["name"]: b for b in par_branches}
    assert set(par_by_name) == {"Branch 0", "Branch 1"}, (
        f"RunParallel must carry exactly the two branch subsegments 'Branch 0' and 'Branch 1'; "
        f"got {sorted(par_by_name)}"
    )
    fast_branch_task = _child_by_name(par_by_name["Branch 0"], "FastBoom")
    slow_branch_task = _child_by_name(par_by_name["Branch 1"], "SlowOk")
    assert fast_branch_task.get("fault") is True, (
        f"the branch that actually raised must carry fault=True on its task subsegment; got "
        f"{fast_branch_task.get('fault')!r}"
    )
    assert slow_branch_task.get("error") is True and slow_branch_task["cause"]["message"] == "Canceled", (
        "the sibling branch's running task, canceled because the other branch failed, must "
        f"carry error=True (E) and cause 'Canceled'; got error={slow_branch_task.get('error')!r} "
        f"cause={slow_branch_task.get('cause')!r}"
    )
    assert par_by_name["Branch 1"].get("error") is True and par_by_name["Branch 1"]["cause"]["message"] == "Canceled", (
        "the canceled sibling's own Branch subsegment must also carry error=True (E) and cause "
        f"'Canceled'; got {par_by_name['Branch 1']!r}"
    )

    # --- Map: a sibling iteration is canceled when another iteration fails ------------------
    desc = _run_past_role_propagation(
        ctx, sfn, map_sm_arn, {"items": [{"mode": "boomfast"}, {"mode": "slow"}]})
    assert desc["status"] == "FAILED", (
        f"a Map with one always-failing iteration and no ToleratedFailurePercentage must fail "
        f"the execution; got {desc['status']!r}"
    )
    _, map_children = _await_full_tree(
        ctx, xray, _trace_root(desc),
        {"RunMap": {"Iteration 0": "MapTask", "Iteration 1": "MapTask"}})
    map_iterations = map_children["RunMap"].get("subsegments", [])
    map_by_name = {it["name"]: it for it in map_iterations}
    assert set(map_by_name) == {"Iteration 0", "Iteration 1"}, (
        f"RunMap must carry exactly the two iteration subsegments 'Iteration 0' and "
        f"'Iteration 1'; got {sorted(map_by_name)}"
    )
    failed_iter_task = _child_by_name(map_by_name["Iteration 0"], "MapTask")
    canceled_iter_task = _child_by_name(map_by_name["Iteration 1"], "MapTask")
    assert failed_iter_task.get("fault") is True, (
        f"the iteration that actually raised (items[0], mode=boomfast) must carry fault=True on "
        f"its task subsegment; got {failed_iter_task.get('fault')!r}"
    )
    assert canceled_iter_task.get("error") is True and canceled_iter_task["cause"]["message"] == "Canceled", (
        "the sibling iteration's running task (items[1], mode=slow), canceled because another "
        f"iteration failed, must carry error=True (E) and cause 'Canceled'; got "
        f"error={canceled_iter_task.get('error')!r} cause={canceled_iter_task.get('cause')!r}"
    )
    assert map_by_name["Iteration 1"].get("error") is True and map_by_name["Iteration 1"]["cause"]["message"] == "Canceled", (
        "the canceled sibling iteration's own subsegment must also carry error=True (E) and "
        f"cause 'Canceled'; got {map_by_name['Iteration 1']!r}"
    )

    # --- StopExecution: the root segment faults, the running task is marked Canceled --------
    stop_exec_arn = _start(ctx, sfn, stop_sm_arn, {})
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        stop_hist_types = [e["type"] for e in _history(sfn, stop_exec_arn)]
        if "TaskStateEntered" in stop_hist_types:
            break
        time.sleep(1.0)
    else:
        raise AssertionError(f"execution {stop_exec_arn} never entered its Task state within 60s")
    sfn.stop_execution(executionArn=stop_exec_arn)
    stop_terminal = _wait_terminal(ctx, sfn, stop_exec_arn, timeout_s=60.0)
    assert stop_terminal["status"] == "ABORTED", (
        f"StopExecution on a running execution must leave it ABORTED; got "
        f"{stop_terminal['status']!r}"
    )

    stop_root, stop_children = _await_full_tree(
        ctx, xray, _trace_root(stop_terminal), {"LongRunning": {}})
    assert stop_root.get("fault") is True, (
        f"StopExecution must fault the root segment; got fault={stop_root.get('fault')!r}"
    )
    long_running = stop_children["LongRunning"]
    assert long_running.get("error") is True and long_running["cause"]["message"] == "Canceled", (
        "the running task subsegment at the moment StopExecution lands must carry error=True "
        f"(E) and cause 'Canceled'; got error={long_running.get('error')!r} "
        f"cause={long_running.get('cause')!r}"
    )


def _parallel_definition(fn_arn: str) -> str:
    return json.dumps({
        "StartAt": "RunParallel",
        "States": {
            "RunParallel": {
                "Type": "Parallel",
                "Branches": [
                    {"StartAt": "FastBoom", "States": {
                        "FastBoom": {"Type": "Task", "Resource": fn_arn,
                                     "Parameters": {"mode": "boomfast"}, "End": True}}},
                    {"StartAt": "SlowOk", "States": {
                        "SlowOk": {"Type": "Task", "Resource": fn_arn,
                                   "Parameters": {"mode": "slow"}, "End": True}}},
                ],
                "End": True,
            },
        },
    })


def _map_definition(fn_arn: str) -> str:
    return json.dumps({
        "StartAt": "RunMap",
        "States": {
            "RunMap": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "MapTask",
                    "States": {
                        "MapTask": {
                            "Type": "Task", "Resource": fn_arn,
                            "Parameters": {"mode.$": "$.mode"}, "End": True,
                        },
                    },
                },
                "End": True,
            },
        },
    })


def _stop_definition(fn_arn: str) -> str:
    return json.dumps({
        "StartAt": "LongRunning",
        "States": {
            "LongRunning": {
                "Type": "Task", "Resource": fn_arn,
                "Parameters": {"mode": "slow"}, "End": True,
            },
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
                Timeout=30, MemorySize=128, Tags={"sim2real": CHECK},
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
    name = ctx.unique_name("sim2real-behav-sfnxray2-")
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
        return arn
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


def _child_by_name(segment: dict, name: str) -> dict:
    for sub in segment.get("subsegments", []):
        if sub.get("name") == name:
            return sub
    raise AssertionError(
        f"no subsegment named {name!r} among {[s.get('name') for s in segment.get('subsegments', [])]}"
    )


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


def _tree_ready(root: dict, children: dict, want: dict) -> bool:
    """Whether the root segment, every wanted state subsegment, and under it every wanted
    branch or iteration subsegment with its task subsegment, has arrived completed."""
    if not root or not _closed(root):
        return False
    for state, nested in want.items():
        if state not in children or not _closed(children[state]):
            return False
        by_name = {sub.get("name"): sub for sub in children[state].get("subsegments", [])}
        for container, task in nested.items():
            if container not in by_name or not _closed(by_name[container]):
                return False
            tasks = {sub.get("name"): sub for sub in by_name[container].get("subsegments", [])}
            if task not in tasks or not _closed(tasks[task]):
                return False
    return True


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_full_tree(ctx, xray, trace_id: str, want: dict) -> tuple[dict, dict]:
    """X-Ray ingestion is incremental: a trace can resolve with only its earliest subsegments
    present, or with one still in progress. Poll BatchGetTraces until the Step Functions root
    segment, every wanted state subsegment and the branch or iteration subsegments nested
    under it have arrived completed."""
    timeout_s = _budget_s(ctx, _XRAY_DEADLINE_S)
    deadline = time.monotonic() + timeout_s
    root, children, origins = {}, {}, []
    while True:
        docs = _trace_documents(xray, trace_id)
        origins = [d.get("origin") for d in docs]
        root, children = _root_and_state_children(docs, trace_id)
        if _tree_ready(root, children, want):
            return root, children
        if time.monotonic() >= deadline:
            break
        time.sleep(_XRAY_INTERVAL_S)
    seen = f"last seen states {sorted(children)} among segment origins {origins}"
    if _budget_spent(ctx):
        raise TimeoutError(
            f"trace {trace_id!r} had not ingested all of {want!r} when the run budget ended; "
            f"{seen}; not graded"
        )
    raise AssertionError(
        f"trace {trace_id!r} never ingested completed subsegments for all of {want!r} within "
        f"{timeout_s:.0f}s; {seen}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
