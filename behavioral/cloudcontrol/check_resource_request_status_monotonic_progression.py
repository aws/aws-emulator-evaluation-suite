"""resource-request-status-monotonic-progression."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-request-status-monotonic-progression"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_STATUS_RANK = {
    "PENDING": 0,
    "IN_PROGRESS": 1,
    "SUCCESS": 2,
    "FAILED": 2,
    "CANCEL_IN_PROGRESS": 1,
    "CANCEL_COMPLETE": 2,
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceRequestStatus for a single request token only ever reports
    OperationStatus values that advance forward, never regressing to an earlier stage."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-cc-mono-")
    resp = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": name})
    )
    token = resp["ProgressEvent"]["RequestToken"]
    seed = [resp["ProgressEvent"]["OperationStatus"]]

    final_pe, history = _wait_for_request(ctx, token, seed_history=seed)
    ctx.on_cleanup(lambda i=final_pe["Identifier"]: _delete_and_wait(ctx, "AWS::SQS::Queue", i))

    assert final_pe["RequestToken"] == token, (
        f"terminal independent read returned a mismatched token: expected {token}, "
        f"got {final_pe.get('RequestToken')} (full history={history})"
    )
    ranks = [_STATUS_RANK[s] for s in history]
    for i in range(len(ranks) - 1):
        assert ranks[i] <= ranks[i + 1], (
            f"OperationStatus regressed at step {i}: {history[i]} -> {history[i + 1]} "
            f"(full history={history})"
        )
    assert final_pe["OperationStatus"] == "SUCCESS", f"create did not reach SUCCESS: {final_pe}"


def _wait_for_request(ctx: Any, token: str, timeout_s: float = 150.0, interval_s: float = 2.0, seed_history=None):
    cc = ctx.client("cloudcontrol")
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    history: list[str] = list(seed_history) if seed_history else []
    deadline = time.monotonic() + timeout_s
    last_pe = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last_pe = resp["ProgressEvent"]
        history.append(last_pe["OperationStatus"])
        if last_pe["OperationStatus"] in terminal:
            return last_pe, history
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state within {timeout_s}s (history={history})")


def _delete_and_wait(ctx: Any, type_name: str, identifier: str, timeout_s: float = 150.0, interval_s: float = 2.0) -> None:
    cc = ctx.client("cloudcontrol")
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise
        return
    token = resp["ProgressEvent"]["RequestToken"]
    _wait_for_request(ctx, token, timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
