"""get-execution-history-page-is-byte-bounded-not-just-count-bounded."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-execution-history-page-is-byte-bounded-not-just-count-bounded"
GROUP = "data-plane"
SERVICES = ["stepfunctions"]

_CHAIN_LEN = 30
_PAD_LEN = 260_000  # under the 262,144-byte (256 KiB) state input/output limit, with JSON overhead
_MAX_RESULTS = 1000  # the API's own ceiling


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sfn-histpage-role-")
    trust = json.dumps(
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
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _chain_definition(n: int) -> str:
    """n Pass states in sequence, each passing its input through unchanged."""
    states = {}
    for i in range(n):
        state = {"Type": "Pass"}
        if i + 1 < n:
            state["Next"] = f"Pass{i + 1}"
        else:
            state["End"] = True
        states[f"Pass{i}"] = state
    return json.dumps({"StartAt": "Pass0", "States": states})


def _create_with_role_propagation(sfn, **kwargs):
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)


def _run_to_terminal(sfn, sm_arn: str, *, input_payload: str, timeout_s: float = 60.0) -> str:
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=input_payload)["executionArn"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            assert last["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {last!r}"
            return exec_arn
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s (last={last!r})")


def _full_history(sfn, exec_arn: str) -> list:
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": _MAX_RESULTS}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            return events


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetExecutionHistory caps a page by response bytes, not just by maxResults: with large
    per-event payloads a page holds fewer events than requested and still returns a nextToken,
    for the identical event-count shape that fits in one page with a tiny payload.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _sfn_role(ctx)
    definition = _chain_definition(_CHAIN_LEN)
    sm_arn = _create_with_role_propagation(
        sfn,
        name=ctx.unique_name("sim2real-sfn-histpage-"),
        definition=definition,
        roleArn=role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn)))

    # Positive control: the same chain shape, tiny payload, fits in a single page.
    small_exec = _run_to_terminal(sfn, sm_arn, input_payload="{}")
    small_page = sfn.get_execution_history(executionArn=small_exec, maxResults=_MAX_RESULTS)
    assert small_page.get("nextToken") is None, (
        f"a tiny-payload run of {_CHAIN_LEN} Pass states should fit in one page of "
        f"maxResults={_MAX_RESULTS}, but got a nextToken"
    )
    total_events = len(small_page["events"])
    assert total_events > 1, "not enough history events to exercise the comparison"

    # Same chain shape, a payload near the 256 KiB state input/output limit on every event.
    pad = "x" * _PAD_LEN
    large_input = json.dumps({"pad": pad})
    assert len(large_input) < 262_144, "fixture payload must stay under the real per-state limit"
    large_exec = _run_to_terminal(sfn, sm_arn, input_payload=large_input)
    large_page = sfn.get_execution_history(executionArn=large_exec, maxResults=_MAX_RESULTS)

    assert large_page.get("nextToken") is not None, (
        f"a page of {len(large_page['events'])} large-payload events returned no nextToken; "
        f"expected one because the full history has {total_events} events of this shape"
    )
    assert len(large_page["events"]) < total_events, (
        f"the large-payload page returned {len(large_page['events'])} events, not fewer than the "
        f"{total_events}-event total that the identical-shape small-payload run returned in one "
        f"page — a page size bounded only by maxResults, not by bytes, would return them all"
    )

    # Pagination still recovers every event, just split differently.
    large_full = _full_history(sfn, large_exec)
    assert len(large_full) == total_events, (
        f"paginating the large-payload execution's full history returned {len(large_full)} events, "
        f"expected the same {total_events} as the identical-shape small-payload run"
    )
    large_ids = [e["id"] for e in large_full]
    assert large_ids == sorted(large_ids), "event ids are not in increasing order across pages"
    assert len(large_ids) == len(set(large_ids)), "duplicate event ids across pagination boundaries"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
