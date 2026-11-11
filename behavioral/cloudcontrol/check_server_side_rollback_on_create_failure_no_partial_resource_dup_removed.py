"""server-side-rollback-on-create-failure-no-partial-resource-dup-removed."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "server-side-rollback-on-create-failure-no-partial-resource-dup-removed"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResource of a queue named ".fifo" with FifoQueue=False ends FAILED with
    GeneralServiceException, and neither Cloud Control nor SQS finds the queue afterwards."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_name = ctx.unique_name("sim2real-cc-nopartial2-") + ".fifo"
    desired_state = json.dumps({"QueueName": queue_name, "FifoQueue": False})
    create = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)
    token = create["ProgressEvent"]["RequestToken"]
    final = _poll_progress(ctx, cc, token, timeout_s=90.0)
    assert final["OperationStatus"] == "FAILED", (
        f"expected the FIFO name/flag mismatch to fail the create, got: {final}"
    )
    # SQS refuses the name and Cloud Control reports it under the catch-all handler code.
    # message varies: StatusMessage carries the downstream SQS Request ID of the refused call.
    assert final.get("ErrorCode") == "GeneralServiceException", (
        f"a FAILED create must carry ErrorCode GeneralServiceException, got: {final}"
    )

    expected_identifier = f"{sqs.meta.endpoint_url}/{account_id}/{queue_name}"
    # Defensive cleanup in case some FIFO-validation nuance let a queue slip through anyway.
    ctx.on_cleanup(lambda: _delete_resource(ctx, cc, "AWS::SQS::Queue", expected_identifier))

    # message varies: Cloud Control embeds the RequestToken of its own internal read in the
    # NotFound message, a token the caller never sees, so only the code is graded.
    code, _ = _error(
        lambda: cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=expected_identifier)
    )
    assert code == "ResourceNotFoundException", (
        f"expected no partially created queue to exist after the FAILED create, got code {code!r}"
    )

    # Independent read at the destination service itself, bypassing Cloud Control's own
    # bookkeeping -- the ground truth the rollback claim actually depends on.
    sqs_code, sqs_message = _error(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert sqs_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected SQS itself to have no record of the queue, got {sqs_code!r}"
    )
    assert sqs_message == "The specified queue does not exist.", (
        f"expected SQS's exact NonExistentQueue message, got {sqs_message!r}"
    )


def _poll_progress(ctx: Any, cc: Any, token: str, timeout_s: float = 120.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"operation did not reach a terminal state within {timeout_s}s: {last}")


def _delete_resource(ctx: Any, cc: Any, type_name: str, identifier: str) -> None:
    """Teardown: an identifier that was never created is fine; a delete that never terminates raises."""
    from botocore.exceptions import ClientError

    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    _poll_progress(ctx, cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60.0)


def _error(fn):
    """The (code, message) of the ClientError fn() raises. Raises if the call SUCCEEDS."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
