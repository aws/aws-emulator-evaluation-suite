"""express-sync-machine-timeoutseconds-shorter-than-wait-yields-timed-out."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "express-sync-machine-timeoutseconds-shorter-than-wait-yields-timed-out"
GROUP = "express_workflows"
SERVICES = ["stepfunctions"]

_TIMEOUT_S = 5
_HOLD_S = 30
_SLACK_S = 20.0


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/statemachine-structure.html
@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
    "dp:api", "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """An EXPRESS state machine's top-level TimeoutSeconds, shorter than a Wait it sits
    in, makes StartSyncExecution block for the full budget then return TIMED_OUT inline
    (never a client error), while a twin with a long budget over a short Wait succeeds.
    """
    role_arn = _sfn_role(ctx)
    short_arn = _create_state_machine(ctx, role_arn, _definition(_TIMEOUT_S, _HOLD_S))
    control_arn = _create_state_machine(ctx, role_arn, _definition(300, 2))

    sfn = ctx.client("stepfunctions")

    start = time.monotonic()
    timed_out = sfn.start_sync_execution(
        stateMachineArn=short_arn, input=json.dumps({"probe": CHECK})
    )
    elapsed = time.monotonic() - start

    assert timed_out["status"] == "TIMED_OUT", (
        f"a synchronous Express execution that outlives its own top-level "
        f"TimeoutSeconds={_TIMEOUT_S} must report status TIMED_OUT inline; got "
        f"{timed_out['status']!r} error={timed_out.get('error')!r} "
        f"cause={timed_out.get('cause')!r}"
    )
    assert timed_out.get("error") == "States.Timeout", (
        f"a synchronous Express machine-level timeout reports error 'States.Timeout' on "
        f"the sync response itself; got {timed_out.get('error')!r} "
        f"cause={timed_out.get('cause')!r}"
    )
    assert "cause" not in timed_out, (
        f"a synchronous Express machine-level timeout sets no cause; got "
        f"cause={timed_out.get('cause')!r}"
    )
    assert "output" not in timed_out, (
        f"a TIMED_OUT sync response carries no output; got output={timed_out.get('output')!r}"
    )

    # The synchronous call blocks for at least the TimeoutSeconds budget, and the response's
    # own startDate/stopDate span shows the execution was cut off by TimeoutSeconds rather
    # than running out the Wait it sits in.
    assert elapsed >= _TIMEOUT_S, (
        f"the synchronous call must block for the full TimeoutSeconds={_TIMEOUT_S} budget "
        f"before returning; it returned after only {elapsed:.2f}s"
    )
    span = (timed_out["stopDate"] - timed_out["startDate"]).total_seconds()
    assert span >= _TIMEOUT_S, (
        f"the response's own startDate/stopDate span must cover the full "
        f"TimeoutSeconds={_TIMEOUT_S} budget; it reported {span:.2f}s"
    )
    assert span < _TIMEOUT_S + _SLACK_S, (
        f"the execution must stop once TimeoutSeconds={_TIMEOUT_S} has elapsed, well inside "
        f"{_TIMEOUT_S + _SLACK_S:.0f}s (the Wait it sits in is {_HOLD_S}s long); its "
        f"startDate/stopDate span is {span:.2f}s"
    )

    # --- Twin control: a long budget over a short Wait succeeds inline instead ---------
    control = sfn.start_sync_execution(
        stateMachineArn=control_arn, input=json.dumps({"probe": CHECK})
    )
    assert control["status"] == "SUCCEEDED", (
        f"the twin with TimeoutSeconds=300 over a 2s Wait must SUCCEED; got "
        f"{control['status']!r} error={control.get('error')!r} "
        f"cause={control.get('cause')!r}"
    )
    control_span = (control["stopDate"] - control["startDate"]).total_seconds()
    assert control_span < _TIMEOUT_S + _SLACK_S, (
        f"the succeeding twin must finish via its 2s Wait, not its unrelated 300s timeout; "
        f"its startDate/stopDate span is {control_span:.2f}s"
    )
    assert control["status"] != timed_out["status"], (
        "a timed-out execution and a succeeded one must not share a status word; both "
        f"reported {control['status']!r}"
    )


def _definition(timeout_seconds: int, hold_seconds: int) -> str:
    return json.dumps(
        {
            "Comment": "EXPRESS machine-level timeout over a Wait",
            "StartAt": "Hold",
            "TimeoutSeconds": timeout_seconds,
            "States": {
                "Hold": {"Type": "Wait", "Seconds": hold_seconds, "Next": "After"},
                "After": {"Type": "Pass", "Result": {"reached": True}, "End": True},
            },
        }
    )


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _sfn_role(ctx) -> str:
    """A role Step Functions can assume. A Wait/Pass machine calls no other service, so it
    needs no permissions policy at all."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnxto-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    """CreateStateMachine(type=EXPRESS), bounded-retrying only the AccessDeniedException
    raised while the freshly created role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnxto-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="EXPRESS",
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
            time.sleep(5.0)
    raise AssertionError(
        f"CreateStateMachine(type=EXPRESS) still AccessDenied 120s after the role was "
        f"created. Last error: {last}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
