"""tracing-enabled-state-machine-publishes-a-trace-and-a-disabled-twin-does-not."""
from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tracing-enabled-state-machine-publishes-a-trace-and-a-disabled-twin-does-not"
GROUP = "observability"
SERVICES = ["stepfunctions", "xray"]

_XRAY_DEADLINE_S = 420.0
_XRAY_INTERVAL_S = 2.0
_ROOT_RE = re.compile(r"Root=(1-[0-9a-f]{8}-[0-9a-f]{24})")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """tracingConfiguration.enabled decides whether an execution's trace is published to
    X-Ray: the traced twin's trace is retrievable at X-Ray, the untraced twin's is not."""
    xray = ctx.client("xray")

    # One role for both machines, so the twins differ only in tracingConfiguration.
    _role_name, role_arn = _create_sfn_role(ctx)
    traced_name, traced_arn = _create_state_machine(ctx, role_arn, tracing=True)
    untraced_name, untraced_arn = _create_state_machine(ctx, role_arn, tracing=False)

    window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=2)

    # X-Ray's sampler may skip a Step Functions-generated trace id; a supplied traceHeader with
    # Sampled=1 (echoed back by StartSyncExecution) makes the positive control deterministic.
    # https://docs.aws.amazon.com/step-functions/latest/dg/concepts-xray-tracing.html
    own_root = _gen_trace_id()
    traced = _sync(ctx, traced_arn, "traced", trace_header=f"Root={own_root};Sampled=1")
    untraced = _sync(ctx, untraced_arn, "untraced")
    driven_at = time.monotonic()

    # --- The traced twin: an exact trace id, resolved at X-Ray --------------------------
    header = traced.get("traceHeader")
    assert header, (
        "a synchronous Express execution of a state machine with tracingConfiguration."
        f"enabled=true must return a traceHeader; the response carried {header!r}"
    )
    root = _root_trace_id(header)
    assert root == own_root, (
        "StartSyncExecution must echo back the Root id supplied on the request's own "
        f"traceHeader when tracingConfiguration.enabled=true; we supplied {own_root!r} and "
        f"the response carried {header!r}"
    )

    trace = _await_trace(xray, root, driven_at)
    assert "Segments" in trace, (
        f"the trace X-Ray returned for {root} carries no Segments key at all; its keys "
        f"were {sorted(trace)}"
    )
    segments = [json.loads(s["Document"]) for s in trace["Segments"]]
    assert segments, (
        f"X-Ray returned trace {root} with an empty Segments list; the rest of the trace "
        f"was { {k: v for k, v in trace.items() if k != 'Segments'} }"
    )
    names = {s.get("name") for s in segments}
    assert traced_name in names, (
        "the ingested trace must contain a segment named after the state machine that "
        f"produced it; expected {traced_name!r} among the segment names {sorted(names)}"
    )
    origins = {s.get("origin") for s in segments if s.get("name") == traced_name}
    assert "AWS::StepFunctions::StateMachine" in origins, (
        "the state machine's own segment must declare origin "
        f"'AWS::StepFunctions::StateMachine'; got {sorted(o for o in origins if o)}"
    )
    assert untraced_name not in names, (
        f"the traced execution's trace must not mention the untraced twin "
        f"{untraced_name!r}; the segment names were {sorted(names)}"
    )

    # --- The same query shape the negative leg will use, proven to work -----------------
    traced_summaries, latency_s = _await_summaries(
        xray, traced_name, window_start, driven_at
    )
    found_ids = {s["Id"] for s in traced_summaries}
    assert root in found_ids, (
        f"the service-filtered GetTraceSummaries query must find the traced execution's "
        f"own trace {root}; it returned {sorted(found_ids)}"
    )

    # --- The untraced twin: absence, on the identical query, bounded by the above --------
    # The positive control above took latency_s on this exact query shape, so hold the
    # absence for >= 3x that before believing it.
    assert untraced["status"] == "SUCCEEDED", (
        "the untraced twin's execution must still SUCCEED — the absence of a trace must "
        f"not be explained by the workflow never running; got {untraced['status']!r} "
        f"error={untraced.get('error')!r} cause={untraced.get('cause')!r}"
    )
    # The hold is three ingestion latencies, each rounded up to 15 s.
    hold_until = driven_at + max(3.0 * math.ceil(latency_s / 15.0) * 15.0, 30.0)
    while True:
        summaries = _summaries(xray, untraced_name, window_start)
        assert summaries == [], (
            "a state machine with tracingConfiguration.enabled=false must publish NO trace "
            f"to X-Ray, yet GetTraceSummaries filtered on {untraced_name!r} returned "
            f"{[s['Id'] for s in summaries]}"
        )
        if time.monotonic() >= hold_until:
            break
        time.sleep(_XRAY_INTERVAL_S)

    # BatchGetTraces for both root ids: exactly one may resolve. If the untraced arm returned
    # no trace header, only the positive id is probed, which is the correct polarity.
    untraced_root = _root_trace_id(untraced.get("traceHeader") or "")
    probe_ids = [i for i in (untraced_root,) if i and i != root]
    resp = xray.batch_get_traces(TraceIds=[root, *probe_ids])
    resolved = {t["Id"] for t in resp["Traces"]}
    assert resolved == {root}, (
        f"BatchGetTraces asked for {[root, *probe_ids]} must resolve exactly the traced "
        f"execution's trace {{{root}}} — the traced one so this leg is not merely "
        "'BatchGetTraces returns nothing', and only that one so the untraced twin's own "
        f"root id was never ingested; it resolved {sorted(resolved)} with "
        f"UnprocessedTraceIds={resp['UnprocessedTraceIds']}"
    )


# A Pass-only workflow never produces a trace even with tracing enabled, so one Task makes
# the flag the only variable; sts:GetCallerIdentity needs no resource of its own.
_DEFINITION = json.dumps(
    {
        "Comment": "one Task with a real downstream call, so there is something for "
        "X-Ray to trace at all",
        "StartAt": "Whoami",
        "States": {
            "Whoami": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
                "Parameters": {},
                "End": True,
            }
        },
    }
)

_TRUST = json.dumps(
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

_XRAY_ACTIONS = [
    "xray:PutTraceSegments",
    "xray:PutTelemetryRecords",
    "xray:GetSamplingRules",
    "xray:GetSamplingTargets",
]


def _root_trace_id(header: str) -> str:
    match = _ROOT_RE.search(header)
    return match.group(1) if match else ""


def _gen_trace_id() -> str:
    """A well-formed X-Ray trace id: 1-<8 hex epoch seconds>-<24 hex random>."""
    return f"1-{int(time.time()):08x}-{os.urandom(12).hex()}"


def _create_sfn_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnxray-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="SimParity draft: sfn x-ray trace publication",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": _XRAY_ACTIONS, "Resource": "*"},
                    {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"},
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


def _create_state_machine(ctx, role_arn: str, *, tracing: bool) -> tuple[str, str]:
    """An EXPRESS state machine (so StartSyncExecution can hand back the trace header),
    bounded-retrying only the AccessDeniedException raised while the freshly created
    role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(
        "sim2real-behav-sfnxray-on-" if tracing else "sim2real-behav-sfnxray-off-"
    )
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_DEFINITION,
                roleArn=role_arn,
                type="EXPRESS",
                tracingConfiguration={"enabled": tracing},
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return name, arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
    raise AssertionError(
        f"CreateStateMachine(type=EXPRESS, tracing={tracing}) still AccessDenied 120s "
        f"after the role granting X-Ray publication was created. Last error: {last}"
    )


_ROLE_PROPAGATION_MARKERS = ("AccessDenied", "not authorized")


def _sync(ctx, sm_arn: str, label: str, *, trace_header: str | None = None) -> dict:
    """StartSyncExecution, bounded-retrying a whole new execution only while the state
    machine's own freshly created role is still propagating — either the trust policy
    (states.amazonaws.com not yet allowed to assume it) or the inline X-Ray/STS grant
    (its one Task's sts:GetCallerIdentity gets AccessDenied) can lag CreateStateMachine."""
    sfn = ctx.client("stepfunctions")
    kwargs = dict(stateMachineArn=sm_arn, input=json.dumps({"probe": CHECK, "arm": label}))
    if trace_header is not None:
        kwargs["traceHeader"] = trace_header
    deadline = time.monotonic() + 90.0
    resp = sfn.start_sync_execution(**kwargs)
    while resp["status"] != "SUCCEEDED" and time.monotonic() < deadline:
        detail = (resp.get("cause") or "") + (resp.get("error") or "")
        if not any(marker in detail for marker in _ROLE_PROPAGATION_MARKERS):
            break
        time.sleep(2.0)
        resp = sfn.start_sync_execution(**kwargs)
    assert resp["status"] == "SUCCEEDED", (
        f"the {label} arm's synchronous Express execution must SUCCEED before its tracing "
        f"is judged; got {resp['status']!r} error={resp.get('error')!r} "
        f"cause={resp.get('cause')!r}"
    )
    return resp


def _summaries(xray, sm_name: str, window_start) -> list[dict]:
    """Trace summaries attributed to one state machine, over the run's own window."""
    out: list[dict] = []
    kwargs = {
        "StartTime": window_start,
        "EndTime": dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=2),
        "FilterExpression": (
            f'service(id(name: "{sm_name}", type: "AWS::StepFunctions::StateMachine"))'
        ),
    }
    while True:
        resp = xray.get_trace_summaries(**kwargs)
        out.extend(resp["TraceSummaries"])
        token = resp.get("NextToken")
        if not token:
            return out
        kwargs["NextToken"] = token


def _await_summaries(xray, sm_name: str, window_start, since) -> tuple[list[dict], float]:
    """Bounded poll until X-Ray has ingested at least one trace for this state machine,
    because segment ingestion and indexing are asynchronous. Returns the summaries plus the
    measured latency, which calibrates the negative arm's hold window."""
    deadline = time.monotonic() + _XRAY_DEADLINE_S
    last: list[dict] = []
    while time.monotonic() < deadline:
        last = _summaries(xray, sm_name, window_start)
        if last:
            return last, max(time.monotonic() - since, 1.0)
        time.sleep(_XRAY_INTERVAL_S)
    raise AssertionError(
        f"X-Ray never indexed a trace for state machine {sm_name!r} within "
        f"{_XRAY_DEADLINE_S}s of a traced execution completing; the filtered query "
        f"returned {len(last)} summaries"
    )


def _await_trace(xray, root: str, since) -> dict:
    """Bounded poll on BatchGetTraces for one exact trace id."""
    deadline = time.monotonic() + _XRAY_DEADLINE_S
    unprocessed = None
    while time.monotonic() < deadline:
        resp = xray.batch_get_traces(TraceIds=[root])
        if resp["Traces"]:
            return resp["Traces"][0]
        unprocessed = resp["UnprocessedTraceIds"]
        time.sleep(_XRAY_INTERVAL_S)
    raise AssertionError(
        f"X-Ray never returned trace {root} — the Root id the traced execution's own "
        f"traceHeader named — within {_XRAY_DEADLINE_S}s ({time.monotonic() - since:.0f}s "
        f"since the execution closed); UnprocessedTraceIds was {unprocessed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
