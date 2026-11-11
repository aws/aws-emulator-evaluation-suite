"""concurrent-delete-and-update-same-identifier-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-and-update-same-identifier-race"
GROUP = "concurrency"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent DeleteResource and UpdateResource on one identifier: exactly one is accepted and
    reaches SUCCESS (verified in native SQS), the other gets ConcurrentOperationException."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-queue-")

    create_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps(
            {
                "QueueName": queue_name,
                "VisibilityTimeout": 30,
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ),
    )
    create_final = _wait_for_terminal(cc, create_resp["ProgressEvent"]["RequestToken"])
    assert create_final["OperationStatus"] == "SUCCESS", f"prerequisite create did not succeed: {create_final}"
    identifier = create_final["Identifier"]

    def _call_update():
        patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 60}])
        return cc.update_resource(TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=patch)

    def _call_delete():
        return cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fu = pool.submit(_safe_call, _call_update)
        fd = pool.submit(_safe_call, _call_delete)
        outcomes = {"update": fu.result(), "delete": fd.result()}

    winners = [name for name, (kind, _) in outcomes.items() if kind == "ok"]
    losers = [name for name, (kind, _) in outcomes.items() if kind == "error"]
    assert len(winners) == 1 and len(losers) == 1, f"unexpected race outcome: {outcomes}"

    loser_code, loser_message = outcomes[losers[0]][1]
    assert loser_code == "ConcurrentOperationException", (
        f"expected the losing {losers[0]} to be rejected with ConcurrentOperationException, got {loser_code}"
    )

    winner = winners[0]
    winner_resp = outcomes[winner][1]
    # The loser names the winner's RequestToken only once the winner's request is registered, so
    # either exact form is AWS's answer depending on how close the two calls land.
    concurrent = f"Concurrent operation found for resource {identifier}"
    expected_loser = (
        concurrent,
        f"{concurrent} with RequestToken {winner_resp['ProgressEvent']['RequestToken']}",
    )
    assert loser_message in expected_loser, (
        f"expected the loser's message to be one of {expected_loser!r}, got {loser_message!r}"
    )
    winner_final = _wait_for_terminal(cc, winner_resp["ProgressEvent"]["RequestToken"])
    assert winner_final["OperationStatus"] == "SUCCESS", f"winning {winner} did not reach SUCCESS: {winner_final}"

    if winner == "update":
        ctx.on_cleanup(lambda: cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=identifier))
        attrs = sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["VisibilityTimeout"])["Attributes"]
        assert attrs["VisibilityTimeout"] == "60", (
            f"native SQS reports VisibilityTimeout={attrs['VisibilityTimeout']!r}; winning update set it to 60"
        )
    else:
        native_code, native_message = _client_error(
            lambda: sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["All"])
        )
        assert native_code == "AWS.SimpleQueueService.NonExistentQueue", (
            f"expected the queue gone from native SQS after the winning delete, got code={native_code}"
        )
        assert native_message == "The specified queue does not exist.", (
            f"expected SQS's NonExistentQueue message, got {native_message!r}"
        )


def _client_error(fn):
    """The (code, message) of the ClientError fn() raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_call(fn):
    try:
        return ("ok", fn())
    except ClientError as exc:
        return ("error", (exc.response["Error"]["Code"], exc.response["Error"]["Message"]))


def _wait_for_terminal(cc, token, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state in {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
