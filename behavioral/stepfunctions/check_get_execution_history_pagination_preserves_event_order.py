"""get-execution-history-pagination-preserves-event-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-execution-history-pagination-preserves-event-order"
GROUP = "data-plane"
SERVICES = ["stepfunctions"]

_CHAIN_LEN = 14


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paginated GetExecutionHistory pages return events in strictly increasing id order, no
    gaps or duplicates across page boundaries."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _chain_definition(_CHAIN_LEN))

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )

    # Unpaginated reference set (default page size comfortably covers our small chain).
    full_events = sfn.get_execution_history(executionArn=exec_arn)["events"]
    assert len(full_events) >= _CHAIN_LEN * 2, "not enough history events to exercise pagination"

    # Now walk the same history with a small page size and a nextToken.
    paged_events = []
    token = None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 3}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        paged_events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            break

    full_ids = [e["id"] for e in full_events]
    paged_ids = [e["id"] for e in paged_events]
    assert paged_ids == full_ids, "paginated event id sequence diverges from the unpaginated reference"
    assert paged_ids == sorted(paged_ids), "event ids are not in increasing order across pages"
    assert len(paged_ids) == len(set(paged_ids)), "duplicate event ids across pagination boundaries"
    assert paged_ids == list(
        range(paged_ids[0], paged_ids[0] + len(paged_ids))
    ), "gap in event id sequence"


def _chain_definition(n: int) -> str:
    states = {}
    for i in range(n):
        name = f"Pass{i}"
        state = {"Type": "Pass"}
        if i + 1 < n:
            state["Next"] = f"Pass{i + 1}"
        else:
            state["End"] = True
        states[name] = state
    return json.dumps({"StartAt": "Pass0", "States": states})


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-sm-")
    last_err = None
    for _ in range(15):
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real", "value": "true"}],
            )
            arn = resp["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
