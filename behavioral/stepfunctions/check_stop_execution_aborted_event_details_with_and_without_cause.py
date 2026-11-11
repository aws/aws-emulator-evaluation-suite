"""stop-execution-aborted-event-details-with-and-without-cause."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-execution-aborted-event-details-with-and-without-cause"
GROUP = "execution-lifecycle"
SERVICES = ["stepfunctions"]

_ERROR = "Sim2Real.OperatorHalt"
_CAUSE = "stopped by the sim2real behavioral suite"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple[str, str]:
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_machine(ctx, sfn, iam) -> str:
    """A STANDARD state machine parked in a long Wait state, with its own execution role."""
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name,
                               AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    definition = json.dumps({"StartAt": "Park",
                             "States": {"Park": {"Type": "Wait", "Seconds": 3600, "End": True}}})
    name = ctx.unique_name("sim2real-behav-sm-stop-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn,
                                           tags=[{"key": "sim2real", "value": CHECK}])["stateMachineArn"]
            break
        except ClientError as exc:
            # IAM propagation: the new role is not yet assumable, and nothing observes that.
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                             "StateMachineDoesNotExist"))
    return arn


def _start(ctx, sfn, sm_arn: str) -> str:
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn)["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    return exec_arn


def _stop_if_running(sfn, exec_arn: str) -> None:
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn)


def _wait_entered(sfn, exec_arn: str) -> None:
    """Poll until the execution's history shows it parked in the Wait state."""
    deadline = time.monotonic() + 60
    types: list = []
    while time.monotonic() < deadline:
        types = [e["type"] for e in sfn.get_execution_history(executionArn=exec_arn)["events"]]
        if "WaitStateEntered" in types:
            return
        time.sleep(1)
    raise AssertionError(f"the execution never entered its Wait state; history types {types!r}")


def _history(sfn, exec_arn: str) -> list:
    events = []
    kwargs = {"executionArn": exec_arn}
    while True:
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        if not page.get("nextToken"):
            return events
        kwargs["nextToken"] = page["nextToken"]


def _terminal_history(sfn, exec_arn: str) -> list:
    """The full history once it records ExecutionAborted (it may trail DescribeExecution)."""
    deadline = time.monotonic() + 60
    events: list = []
    while time.monotonic() < deadline:
        events = _history(sfn, exec_arn)
        if any(e["type"] == "ExecutionAborted" for e in events):
            return events
        time.sleep(1)
    raise AssertionError(f"history never recorded ExecutionAborted: {[e['type'] for e in events]!r}")


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopExecution on a RUNNING execution ends it ABORTED and records exactly what was supplied:
    error and cause in DescribeExecution and executionAbortedEventDetails, or neither and empty
    details. A second StopExecution is accepted, answers the original stopDate and changes nothing.
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    sm_arn = _wait_machine(ctx, sfn, iam)
    with_cause = _start(ctx, sfn, sm_arn)
    bare = _start(ctx, sfn, sm_arn)
    _wait_entered(sfn, with_cause)
    _wait_entered(sfn, bare)

    stopped = sfn.stop_execution(executionArn=with_cause, error=_ERROR, cause=_CAUSE)["stopDate"]
    sfn.stop_execution(executionArn=bare)

    d1 = sfn.describe_execution(executionArn=with_cause)
    assert d1["status"] == "ABORTED", f"stopped execution is {d1['status']!r}, expected 'ABORTED'"
    assert (d1.get("error"), d1.get("cause")) == (_ERROR, _CAUSE), (
        f"DescribeExecution error/cause are {d1.get('error')!r} / {d1.get('cause')!r}"
    )
    assert d1.get("stopDate") == stopped, (
        f"DescribeExecution stopDate {d1.get('stopDate')!r} differs from StopExecution's {stopped!r}"
    )
    assert d1["stopDate"] >= d1["startDate"], (
        f"stopDate {d1['stopDate']!r} precedes startDate {d1['startDate']!r}"
    )
    d2 = sfn.describe_execution(executionArn=bare)
    assert d2["status"] == "ABORTED", f"bare-stopped execution is {d2['status']!r}, expected 'ABORTED'"
    assert "error" not in d2 and "cause" not in d2, (
        f"a stop with no error/cause reports error={d2.get('error')!r} cause={d2.get('cause')!r}"
    )

    h1 = _terminal_history(sfn, with_cause)
    h2 = _terminal_history(sfn, bare)
    for label, events in (("with cause", h1), ("bare", h2)):
        types = [e["type"] for e in events]
        assert types == ["ExecutionStarted", "WaitStateEntered", "ExecutionAborted"], (
            f"history of the {label} stop is {types!r}"
        )
    assert h1[-1].get("executionAbortedEventDetails") == {"error": _ERROR, "cause": _CAUSE}, (
        f"ExecutionAborted details are {h1[-1].get('executionAbortedEventDetails')!r}"
    )
    assert h2[-1].get("executionAbortedEventDetails") == {}, (
        f"a bare stop's ExecutionAborted details are {h2[-1].get('executionAbortedEventDetails')!r}, expected {{}}"
    )
    newest = sfn.get_execution_history(executionArn=with_cause, reverseOrder=True, maxResults=1)["events"]
    assert [e["type"] for e in newest] == ["ExecutionAborted"], (
        f"reverseOrder's first event is {[e['type'] for e in newest]!r}, expected ExecutionAborted"
    )

    again = sfn.stop_execution(executionArn=with_cause, error="Sim2Real.Second", cause="second stop")
    assert again["stopDate"] == stopped, (
        f"a repeated stop answered stopDate {again['stopDate']!r}, not the original {stopped!r}"
    )
    after = sfn.describe_execution(executionArn=with_cause)
    assert (after["status"], after.get("error"), after.get("cause")) == ("ABORTED", _ERROR, _CAUSE), (
        f"a repeated stop rewrote the execution to {after['status']!r} {after.get('error')!r} "
        f"{after.get('cause')!r}"
    )
    assert _history(sfn, with_cause) == h1, "a repeated stop changed the execution history"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
