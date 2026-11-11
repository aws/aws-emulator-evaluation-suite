"""server-enforced-concurrent-operation-limit-rejected."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-enforced-concurrent-operation-limit-rejected"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateResource calls on one queue: exactly one is refused with
    ConcurrentOperationException (synchronously, naming the resource and the winner's RequestToken,
    or as its FAILED ErrorCode), and SQS reports the winner's exact VisibilityTimeout."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    name = ctx.unique_name("sim2real-cc-conc-")
    create_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}),
    )
    create_final = _poll_request_status(cc, create_resp["ProgressEvent"]["RequestToken"], timeout_s=90.0)
    assert create_final["OperationStatus"] == "SUCCESS", f"setup create failed: {create_final}"
    identifier = create_final["Identifier"]
    ctx.on_cleanup(lambda: _best_effort(lambda: sqs.delete_queue(QueueUrl=identifier)))

    # label -> (patch document, the VisibilityTimeout it would set if applied)
    patches = {"a": (json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 45}]), "45"),
               "b": (json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 75}]), "75")}

    def _submit(label: str) -> tuple[str, str, str, str | None]:
        patch, _ = patches[label]
        try:
            resp = cc.update_resource(TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=patch)
            return (label, "token", resp["ProgressEvent"]["RequestToken"], None)
        except ClientError as e:
            return (label, "error", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_submit, "a")
        fut_b = pool.submit(_submit, "b")
        result_a = fut_a.result()
        result_b = fut_b.result()

    conflict_seen = False
    conflict_message = None
    winner_label = None
    winner_token = None
    for label, kind, value, message in (result_a, result_b):
        if kind == "error":
            assert value == "ConcurrentOperationException", (
                f"expected a rejected overlapping UpdateResource to fail with "
                f"ConcurrentOperationException, got {value!r}"
            )
            conflict_seen = True
            conflict_message = message
        else:
            winner_label, winner_token = label, value

    if not conflict_seen:
        # Neither call was rejected synchronously: both were accepted async, so the conflict
        # (if the constraint is real) must show up as one request's terminal FAILED status.
        final_a = _poll_request_status(cc, result_a[2], timeout_s=90.0) if result_a[1] == "token" else None
        final_b = _poll_request_status(cc, result_b[2], timeout_s=90.0) if result_b[1] == "token" else None
        terminals = [(result_a[0], final_a), (result_b[0], final_b)]
        terminals = [(label, f) for label, f in terminals if f is not None]
        successes = [(label, f) for label, f in terminals if f["OperationStatus"] == "SUCCESS"]
        failures = [(label, f) for label, f in terminals if f["OperationStatus"] == "FAILED"]
        assert len(successes) == 1 and len(failures) == 1, (
            f"expected exactly one SUCCESS and one FAILED among overlapping updates, got {terminals}"
        )
        # message varies: no asynchronous FAILED form has been observed, so only the code is graded
        assert failures[0][1].get("ErrorCode") == "ConcurrentOperationException", (
            f"expected the losing overlapping update's FAILED status to carry "
            f"ConcurrentOperationException, got {failures[0][1].get('ErrorCode')!r}"
        )
        winner_label, winner_token = successes[0][0], successes[0][1]["RequestToken"]
    else:
        assert winner_token is not None, "expected the non-conflicting call to have returned a RequestToken"
        expected_message = (
            f"Concurrent operation found for resource {identifier} with RequestToken {winner_token}"
        )
        assert conflict_message == expected_message, (
            f"expected the rejection to name the resource and the in-flight request: "
            f"{expected_message!r}, got {conflict_message!r}"
        )
        winner_final = _poll_request_status(cc, winner_token, timeout_s=90.0)
        assert winner_final["OperationStatus"] == "SUCCESS", f"the non-conflicting update should succeed: {winner_final}"

    # Positive control: the winning update actually took effect, verified at the native SQS
    # destination -- not through Cloud Control's own index -- so a handler that reports SUCCESS
    # without actually writing through cannot pass.
    expected_visibility_timeout = patches[winner_label][1]
    native = sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["VisibilityTimeout"])
    assert native["Attributes"]["VisibilityTimeout"] == expected_visibility_timeout, (
        f"expected the winning UpdateResource (patch {winner_label!r}) to have set native "
        f"VisibilityTimeout={expected_visibility_timeout!r}, SQS reports "
        f"{native['Attributes'].get('VisibilityTimeout')!r}"
    )


def _poll_request_status(cc: Any, token: str, *, timeout_s: float, interval_s: float = 2.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached a terminal state in {timeout_s}s: {last}")


def _best_effort(fn: Any) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
