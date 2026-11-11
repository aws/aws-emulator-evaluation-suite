"""deep-sfn-3-parallel-retry-reruns-completed-sibling."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-3-parallel-retry-reruns-completed-sibling"
GROUP = "parallel"
SERVICES = ["stepfunctions"]

_INTERVAL_S = 5
_TRANSIENT = "Sim2Real.Transient"
# Branch B fails only on the Parallel state's FIRST attempt: its gate compares the live clock with
# the execution's start, and the first attempt reaches it within ~1 s while the retry, IntervalSeconds
# later, cannot. No external store is needed to tell the attempts apart.
_GATE_MS = 3000
_DEFINITION = {
    "StartAt": "Fan",
    "States": {
        "Fan": {
            "Type": "Parallel",
            "Branches": [
                {"StartAt": "Sibling",
                 "States": {"Sibling": {"Type": "Pass", "Result": "sibling-done", "End": True}}},
                {"StartAt": "Gate",
                 "States": {
                     "Gate": {
                         "Type": "Choice", "QueryLanguage": "JSONata",
                         "Choices": [{
                             "Condition": "{% ($toMillis($now()) - $toMillis($states.context.Execution."
                                          f"StartTime)) < {_GATE_MS} %}}",
                             "Next": "Flake",
                         }],
                         "Default": "Steady",
                     },
                     "Flake": {"Type": "Fail", "Error": _TRANSIENT, "Cause": "first attempt only"},
                     "Steady": {"Type": "Pass", "Result": "flaky-done", "End": True},
                 }},
            ],
            "Retry": [{"ErrorEquals": [_TRANSIENT], "IntervalSeconds": _INTERVAL_S, "MaxAttempts": 2,
                       "BackoffRate": 1.0}],
            "End": True,
        },
    },
}


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Retry on a Parallel state re-runs the whole Parallel, including the sibling branch that
    already succeeded: Sibling and Gate run twice, the re-run IntervalSeconds after the first.
    """
    role_arn = _sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DEFINITION)
    exec_arn = _start(ctx, sm_arn, {})
    desc = _wait_terminal(ctx, exec_arn)
    events = _history(ctx, exec_arn)
    types = [e["type"] for e in events]
    assert desc["status"] == "SUCCEEDED", (
        f"the retried Parallel must SUCCEED on its second attempt; got {desc['status']!r} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r} history={types!r}"
    )
    assert json.loads(desc["output"]) == ["sibling-done", "flaky-done"], (
        f"output must be the second attempt's branch results; got {desc['output']!r}"
    )

    sib = _entered(events, "Sibling")
    counts = {s: len(_entered(events, s)) for s in ("Sibling", "Gate", "Flake", "Steady")}
    assert counts == {"Sibling": 2, "Gate": 2, "Flake": 1, "Steady": 1}, (
        f"a Parallel-level Retry must re-run BOTH branches, including the sibling that already "
        f"succeeded; state entry counts were {counts!r} in history {types!r}"
    )
    flake = _entered(events, "Flake")[0]
    assert flake["id"] < sib[1]["id"], (
        f"the attempt-1 failure (event {flake['id']}) must precede the sibling's re-run (event "
        f"{sib[1]['id']}); history {types!r}"
    )
    # The IntervalSeconds gap shows the re-run is the Retry, not a duplicate within attempt 1.
    gap = (sib[1]["timestamp"] - sib[0]["timestamp"]).total_seconds()
    assert gap >= _INTERVAL_S - 0.5, (
        f"the sibling's second run must come from the Retry, at least IntervalSeconds={_INTERVAL_S} "
        f"after its first; the two entries were {gap:.2f}s apart"
    )
    p_in, p_out = _state_span(events, "Fan")
    assert p_in <= flake["timestamp"] < sib[1]["timestamp"] <= p_out, (
        "both attempts must happen inside the one Parallel state span; "
        f"entered={p_in.isoformat()} flake={flake['timestamp'].isoformat()} "
        f"sibling#2={sib[1]['timestamp'].isoformat()} exited={p_out.isoformat()}"
    )


_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns a stale value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _sfn_role(ctx) -> str:
    """A role Step Functions can assume. These definitions call no other service, so it needs no
    permissions policy at all."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sfn-interp-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn, definition, **extra) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while the fresh
    role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-interp-sm-")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}], **extra,
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _start(ctx, sm_arn, payload) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]

    def _stop():
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)

    ctx.on_cleanup(_stop)
    return exec_arn


def _wait_terminal(ctx, exec_arn, timeout_s=150.0) -> dict:
    sfn = ctx.client("stepfunctions")
    return _poll_until(lambda: sfn.describe_execution(executionArn=exec_arn),
                       lambda d: d["status"] != "RUNNING", timeout_s=timeout_s,
                       description=f"execution {exec_arn} leaving RUNNING")


def _history(ctx, exec_arn) -> list:
    sfn = ctx.client("stepfunctions")
    events, kwargs = [], {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextToken"):
            return sorted(events, key=lambda e: e["id"])
        kwargs["nextToken"] = resp["nextToken"]


def _entered(events, state) -> list:
    return [e for e in events if e.get("stateEnteredEventDetails", {}).get("name") == state]


def _exited(events, state) -> list:
    return [e for e in events if e.get("stateExitedEventDetails", {}).get("name") == state]


def _state_span(events, state):
    """(entered, exited) timestamps of a state visited exactly once."""
    en, ex = _entered(events, state), _exited(events, state)
    assert len(en) == 1 and len(ex) == 1, (
        f"state {state!r} must be entered and exited exactly once; got {len(en)} entered / "
        f"{len(ex)} exited in {[e['type'] for e in events]!r}"
    )
    return en[0]["timestamp"], ex[0]["timestamp"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
