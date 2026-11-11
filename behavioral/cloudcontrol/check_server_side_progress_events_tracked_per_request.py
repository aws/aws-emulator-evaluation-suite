"""server-side-progress-events-tracked-per-request."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-progress-events-tracked-per-request"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResource starts non-terminal; every poll of its RequestToken reports the same
    TypeName/Operation/RequestToken until SUCCESS, whose Identifier equals the real queue URL."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-cc-progress-")

    create_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps(
            {"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ),
    )
    pe = create_resp["ProgressEvent"]
    token = pe["RequestToken"]

    assert pe["TypeName"] == "AWS::SQS::Queue"
    assert pe["Operation"] == "CREATE"
    assert pe["OperationStatus"] in ("PENDING", "IN_PROGRESS"), (
        f"expected CreateResource to be asynchronous (non-terminal initial status), got {pe['OperationStatus']!r}"
    )

    observed_statuses: list[str] = [pe["OperationStatus"]]
    final = _poll_request_status(
        cc,
        token,
        type_name="AWS::SQS::Queue",
        operation="CREATE",
        timeout_s=90.0,
        interval_s=2.0,
        observed=observed_statuses,
    )

    assert final["OperationStatus"] == "SUCCESS", f"create did not reach SUCCESS: {final}"
    assert final["RequestToken"] == token, "RequestToken must stay constant across status polls"
    assert final["TypeName"] == "AWS::SQS::Queue"
    assert final["Operation"] == "CREATE"
    identifier = final["Identifier"]
    assert identifier, "SUCCESS status must carry the created resource's Identifier"
    ctx.on_cleanup(lambda: _best_effort_delete_queue(sqs, identifier))

    assert observed_statuses[0] in ("PENDING", "IN_PROGRESS"), observed_statuses
    assert observed_statuses[-1] == "SUCCESS", observed_statuses

    real_url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    assert identifier == real_url, f"tracked Identifier {identifier!r} != actual queue URL {real_url!r}"


def _poll_request_status(
    cc: Any,
    token: str,
    *,
    type_name: str,
    operation: str,
    timeout_s: float,
    interval_s: float,
    observed: list[str],
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        assert last["RequestToken"] == token, (
            f"poll for {token} returned RequestToken {last.get('RequestToken')!r}, expected {token!r}"
        )
        assert last["TypeName"] == type_name, (
            f"poll for {token} returned TypeName {last.get('TypeName')!r}, expected {type_name!r}"
        )
        assert last["Operation"] == operation, (
            f"poll for {token} returned Operation {last.get('Operation')!r}, expected {operation!r}"
        )
        observed.append(last["OperationStatus"])
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached a terminal state in {timeout_s}s: {last}")


def _best_effort_delete_queue(sqs: Any, queue_url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=queue_url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
