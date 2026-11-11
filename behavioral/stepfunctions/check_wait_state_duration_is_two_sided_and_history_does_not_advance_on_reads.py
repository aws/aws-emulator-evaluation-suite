"""wait-state-duration-is-two-sided-and-history-does-not-advance-on-reads."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wait-state-duration-is-two-sided-and-history-does-not-advance-on-reads"
GROUP = "wait_state"
SERVICES = ["stepfunctions"]

_SHORT_WAIT = 2
# Long enough that the three freeze-detector reads below comfortably finish while the
# execution is still parked in the Wait, even on a slow link.
_LONG_WAIT = 20
_SLACK_S = 8.0
_DIFF_SLACK_S = 3.0
_ABSOLUTE_OFFSET_S = 20
_ABSOLUTE_UPPER_S = 25.0
_FREEZE_READS = 3


# timing:real-time — workflow: 20 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Wait state's measured duration is bounded on BOTH sides by its Seconds, the
    difference between two Waits equals the difference in Seconds, an absolute Timestamp
    Wait respects the live clock, and reading history does not advance the execution."""
    _role_name, role_arn = _create_sfn_role(ctx)

    # Twins differing only in Seconds, started in the same instant so the fixed overhead
    # each one pays is the same and cancels in the difference below.
    short_arn = _create_state_machine(ctx, role_arn, _seconds_definition(_SHORT_WAIT))
    long_arn = _create_state_machine(ctx, role_arn, _seconds_definition(_LONG_WAIT))
    # The absolute Timestamp Wait runs alongside the twins; it is minted from the live clock.
    # Step Functions accepts RFC3339 with a trailing Z and no sub-second part.
    target = (
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=_ABSOLUTE_OFFSET_S)
    ).replace(microsecond=0)
    target_iso = target.strftime("%Y-%m-%dT%H:%M:%SZ")
    abs_arn = _create_state_machine(ctx, role_arn, _timestamp_definition(target_iso))
    short_exec = _start(ctx, short_arn, {"probe": CHECK})
    long_exec = _start(ctx, long_arn, {"probe": CHECK})
    abs_exec = _start(ctx, abs_arn, {"probe": CHECK})

    # --- Freeze detector, while the long Wait is demonstrably still pending ------------
    # A read must not move the interpreter forward. Taken before either terminal poll so the
    # execution is genuinely mid-Wait.
    reads = []
    for _ in range(_FREEZE_READS):
        status = ctx.client("stepfunctions").describe_execution(
            executionArn=long_exec
        )["status"]
        reads.append((status, _fingerprint(_history(ctx, long_exec))))
    assert reads[0][0] == "RUNNING", (
        f"the {_LONG_WAIT}s-Wait execution must still be RUNNING when the freeze detector "
        f"runs, otherwise it proves nothing; it was {reads[0][0]!r}"
    )
    assert len({fp for _status, fp in reads}) == 1, (
        f"{_FREEZE_READS} consecutive GetExecutionHistory calls against an execution "
        "parked in a Wait must return the IDENTICAL event list — reading must not advance "
        f"the state machine. The {_FREEZE_READS} fingerprints were "
        f"{[fp for _s, fp in reads]}"
    )
    assert {status for status, _fp in reads} == {"RUNNING"}, (
        "the execution must remain RUNNING across the freeze reads; the statuses observed "
        f"were {[s for s, _fp in reads]}"
    )

    short_desc = _wait_terminal(ctx, short_exec, timeout_s=_budget_s(ctx, 120.0))
    long_desc = _wait_terminal(ctx, long_exec, timeout_s=_budget_s(ctx, 120.0))
    for label, desc in (("short", short_desc), ("long", long_desc)):
        assert desc["status"] == "SUCCEEDED", (
            f"the {label} Wait execution must SUCCEED before its duration means "
            f"anything; got {desc['status']} cause={desc.get('cause')!r}"
        )

    short_s = _wait_duration(ctx, short_exec)
    long_s = _wait_duration(ctx, long_exec)

    # --- Two-sided per-Wait bounds -----------------------------------------------------
    for label, seconds, observed in (
        ("short", _SHORT_WAIT, short_s),
        ("long", _LONG_WAIT, long_s),
    ):
        assert observed >= seconds, (
            f"the {label} Wait must not exit before its Seconds={seconds} have elapsed; "
            f"the history says it sat in the Wait for only {observed:.2f}s"
        )
        assert observed < seconds + _SLACK_S, (
            f"the {label} Wait must exit promptly after Seconds={seconds}, inside "
            f"{seconds + _SLACK_S:.1f}s; the history says it sat there {observed:.2f}s"
        )

    # --- The difference cancels the fixed overhead ------------------------------------
    expected_diff = float(_LONG_WAIT - _SHORT_WAIT)
    observed_diff = long_s - short_s
    assert abs(observed_diff - expected_diff) <= _DIFF_SLACK_S, (
        f"the difference between a Seconds={_LONG_WAIT} Wait and a Seconds={_SHORT_WAIT} "
        f"Wait must be {expected_diff:.0f}s +/- {_DIFF_SLACK_S}s, since the per-execution "
        f"overhead is identical and cancels; measured {observed_diff:.2f}s "
        f"(long {long_s:.2f}s, short {short_s:.2f}s)"
    )

    # --- An absolute Timestamp Wait, computed from the live clock ----------------------
    abs_desc = _wait_terminal(ctx, abs_exec, timeout_s=_budget_s(ctx, 120.0))
    assert abs_desc["status"] == "SUCCEEDED", (
        f"the absolute-Timestamp Wait execution must SUCCEED; got {abs_desc['status']} "
        f"cause={abs_desc.get('cause')!r}"
    )

    exited_at = _wait_exit_timestamp(ctx, abs_exec)
    overshoot = (exited_at - target).total_seconds()
    assert overshoot >= 0.0, (
        f'a Wait with Timestamp="{target_iso}" must not exit before that instant; the '
        f"history says it exited at {exited_at.isoformat()}, {-overshoot:.2f}s early"
    )
    assert overshoot < _ABSOLUTE_UPPER_S, (
        f'a Wait with Timestamp="{target_iso}" must exit within {_ABSOLUTE_UPPER_S}s of '
        f"that instant; the history says it exited at {exited_at.isoformat()}, "
        f"{overshoot:.2f}s late"
    )



_WAIT_STATE = "Hold"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _seconds_definition(seconds: int) -> str:
    return json.dumps(
        {
            "Comment": "relative Wait, measured from its own history events",
            "StartAt": _WAIT_STATE,
            "States": {
                _WAIT_STATE: {"Type": "Wait", "Seconds": seconds, "Next": "Done"},
                "Done": {"Type": "Pass", "Result": {"waited": seconds}, "End": True},
            },
        }
    )


def _timestamp_definition(iso: str) -> str:
    return json.dumps(
        {
            "Comment": "absolute Wait against an instant minted from the live clock",
            "StartAt": _WAIT_STATE,
            "States": {
                _WAIT_STATE: {"Type": "Wait", "Timestamp": iso, "Next": "Done"},
                "Done": {"Type": "Pass", "Result": {"until": iso}, "End": True},
            },
        }
    )


def _create_sfn_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnwait-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="SimParity draft: two-sided Wait timing",
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
                    {
                        "Effect": "Allow",
                        "Action": ["states:DescribeStateMachine"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while
    the freshly created role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnwait-")
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError("CreateStateMachine accepting the fresh role: the run budget ended first; not graded")
    raise AssertionError(
        f"CreateStateMachine still AccessDenied before its deadline after the role was created. "
        f"Last error: {last}"
    )


def _start(ctx, sm_arn: str, payload: dict) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
    return exec_arn


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"execution {exec_arn} leaving RUNNING: the run budget ended first; not graded")
    raise AssertionError(
        f"execution {exec_arn} still RUNNING after {timeout_s}s; the longest Wait in this "
        f"check is {max(_LONG_WAIT, _ABSOLUTE_OFFSET_S)}s. Last: {last!r}"
    )


def _history(ctx, exec_arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    events: list[dict] = []
    kwargs = {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return sorted(events, key=lambda e: e["id"])
        kwargs["nextToken"] = token


def _fingerprint(events: list[dict]) -> str:
    return "|".join(f"{e['id']}:{e['type']}" for e in events)


def _wait_state_events(ctx, exec_arn: str) -> tuple[dict, dict]:
    events = _history(ctx, exec_arn)
    entered = [
        e
        for e in events
        if e.get("stateEnteredEventDetails", {}).get("name") == _WAIT_STATE
    ]
    exited = [
        e
        for e in events
        if e.get("stateExitedEventDetails", {}).get("name") == _WAIT_STATE
    ]
    assert len(entered) == 1 and len(exited) == 1, (
        f"history must record the {_WAIT_STATE} Wait entered exactly once and exited "
        f"exactly once; got {len(entered)} entered / {len(exited)} exited out of "
        f"{[e['type'] for e in events]}"
    )
    return entered[0], exited[0]


def _wait_duration(ctx, exec_arn: str) -> float:
    entered, exited = _wait_state_events(ctx, exec_arn)
    return (exited["timestamp"] - entered["timestamp"]).total_seconds()


def _wait_exit_timestamp(ctx, exec_arn: str):
    _entered, exited = _wait_state_events(ctx, exec_arn)
    return exited["timestamp"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
