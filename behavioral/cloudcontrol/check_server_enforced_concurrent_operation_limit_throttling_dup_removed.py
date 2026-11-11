"""server-enforced-concurrent-operation-limit-throttling-dup-removed."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-enforced-concurrent-operation-limit-throttling-dup-removed"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Six concurrent UpdateResource calls on one queue: at least one is accepted and applies, any
    refused one fails with ConcurrentOperationException and no other error, the settled queue
    holds one successful racer's value, and a later sequential update applies."""
    cc = ctx.client("cloudcontrol")
    queue_name = ctx.unique_name("sim2real-cc-concurrency2-")
    create = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps(
            {
                "QueueName": queue_name,
                "VisibilityTimeout": 30,
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ),
    )
    final = _poll_progress(
        ctx, cc, create["ProgressEvent"]["RequestToken"], timeout_s=_budget_s(ctx, 120.0), capped=True
    )
    assert final["OperationStatus"] == "SUCCESS", final
    identifier = final["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(ctx, cc, "AWS::SQS::Queue", identifier))

    def _race(i: int):
        patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 31 + i}])
        try:
            resp = cc.update_resource(
                TypeName="AWS::SQS::Queue",
                Identifier=identifier,
                PatchDocument=patch,
                ClientToken=ctx.unique_name(f"sim2real-cc-race2-{i}-"),
            )
            return ("ok", resp["ProgressEvent"]["RequestToken"], 31 + i)
        except Exception as err:
            code = _error_code_of(err)
            return ("error", code, 31 + i)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(_race, range(6)))

    oks = [r for r in results if r[0] == "ok"]
    concurrent_errors = [r for r in results if r[0] == "error" and r[1] == "ConcurrentOperationException"]
    other_errors = [r for r in results if r[0] == "error" and r[1] != "ConcurrentOperationException"]

    # ConcurrentOperationException is thrown while another operation runs on the resource; a target
    # that runs the racers one after another refuses none, so a refusal is allowed, not required.
    assert not other_errors, f"unexpected non-ConcurrentOperation errors among racers: {other_errors}"
    assert len(oks) + len(concurrent_errors) == len(results), results
    assert len(oks) >= 1, f"expected at least one racing UpdateResource to be accepted: {results}"

    # Let every accepted racer settle before issuing the follow-up. Real Cloud Control
    # serializes multiple accepted-but-queued updates against the same resource identifier one
    # after another, so with up to six racers the tail update may not settle for a while --
    # scale the bound with how many were actually accepted instead of a fixed short timeout.
    applied = set()
    for _, token, value in oks:
        settled = _poll_progress(ctx, cc, token, timeout_s=_budget_s(ctx, 90.0 * len(oks)), capped=True)
        if settled["OperationStatus"] == "SUCCESS":
            applied.add(value)
    assert applied, f"no accepted racing UpdateResource reached SUCCESS: {results}"
    # SetQueueAttributes documents up to 60 s for an attribute change to propagate.
    timeout_s = _budget_s(ctx, 60.0)
    deadline = time.monotonic() + timeout_s
    while True:
        settled = json.loads(
            cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)["ResourceDescription"][
                "Properties"
            ]
        ).get("VisibilityTimeout")
        if str(settled) in {str(v) for v in applied} or time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if str(settled) not in {str(v) for v in applied} and _budget_spent(ctx):
        raise TimeoutError("the settled VisibilityTimeout: the run budget ended first; not graded")
    assert str(settled) in {str(v) for v in applied}, (
        f"after the racers settled the queue holds VisibilityTimeout={settled!r} for "
        f"{timeout_s:.0f}s, which no successful racer wrote; the successful racers wrote "
        f"{sorted(applied)}"
    )

    follow_up = cc.update_resource(
        TypeName="AWS::SQS::Queue",
        Identifier=identifier,
        PatchDocument=json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 45}]),
        ClientToken=ctx.unique_name("sim2real-cc-followup2-"),
    )
    follow_final = _poll_progress(
        ctx, cc, follow_up["ProgressEvent"]["RequestToken"], timeout_s=_budget_s(ctx, 120.0), capped=True
    )
    assert follow_final["OperationStatus"] == "SUCCESS", follow_final

    # Independent read at the destination: the sequential follow-up actually applied,
    # proving the resource is live and not merely reporting SUCCESS while stuck.
    got = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert str(props.get("VisibilityTimeout")) == "45", (
        f"expected the sequential follow-up's VisibilityTimeout=45 to have been applied, "
        f"got {props.get('VisibilityTimeout')!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_progress(
    ctx: Any, cc: Any, token: str, timeout_s: float = 120.0, interval_s: float = 2.0, capped: bool = False
) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    if capped and _budget_spent(ctx):
        raise TimeoutError(f"operation {token} reaching a terminal state: the run budget ended first; not graded")
    raise AssertionError(f"operation did not reach a terminal state within {timeout_s:.0f}s: {last}")


def _delete_resource(ctx: Any, cc: Any, type_name: str, identifier: str) -> None:
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        # SQS takes up to 60 s to delete a queue; Cloud Control reports DELETE past that.
        done = _poll_progress(ctx, cc, resp["ProgressEvent"]["RequestToken"], timeout_s=300.0)
        if done["OperationStatus"] != "SUCCESS" and done.get("ErrorCode") != "NotFound":
            raise RuntimeError(f"DeleteResource of {identifier} ended {done}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


def _error_code_of(err: Exception) -> str | None:
    from botocore.exceptions import ClientError

    if isinstance(err, ClientError):
        return err.response["Error"]["Code"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
