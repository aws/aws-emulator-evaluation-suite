"""update-resource-nonexistent-fails-async-not-sync."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-resource-nonexistent-fails-async-not-sync"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _wait_terminal(cc, request_token: str, *, timeout_s: int = 90, interval_s: float = 2.0) -> dict:
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in TERMINAL_STATUSES:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"request {request_token} did not reach a terminal status within {timeout_s}s. Last: {last!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateResource on a nonexistent SQS queue fails synchronously with ResourceNotFoundException
    (HTTP 400) and records no ResourceRequest, while the same update on a real queue does.
    """
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    type_name = "AWS::SQS::Queue"
    # A schema-valid patch: the resource schema types MessageRetentionPeriod as an integer.
    patch_document = json.dumps(
        [{"op": "replace", "path": "/MessageRetentionPeriod", "value": 345600}]
    )

    # Positive control: the same call, against a queue that exists. Without it, "no
    # ResourceRequest recorded" below would also pass on a target that never records any.
    control_queue_name = ctx.unique_name("sim2real-behav-cc-queue-")
    control_queue_url = sqs.create_queue(
        QueueName=control_queue_name, tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=control_queue_url))
    control_identifier = control_queue_url

    control_resp = cc.update_resource(
        TypeName=type_name,
        Identifier=control_identifier,
        PatchDocument=patch_document,
    )
    control_token = control_resp["ProgressEvent"]["RequestToken"]
    control_event = _wait_terminal(cc, control_token)
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"positive control UpdateResource against an existing queue failed: {control_event!r}"
    )
    control_attrs = sqs.get_queue_attributes(
        QueueUrl=control_queue_url, AttributeNames=["MessageRetentionPeriod"]
    )["Attributes"]
    assert control_attrs["MessageRetentionPeriod"] == "345600", (
        f"positive control patch did not take effect: {control_attrs!r}"
    )
    control_summary = _find_request_summary_for_identifier(cc, type_name, control_identifier)
    assert control_summary is not None, (
        "the positive control's successful UpdateResource left no ResourceRequest behind -- "
        "this target does not record requests for AWS::SQS::Queue, which would make the "
        "negative below vacuous"
    )

    queue_name = ctx.unique_name("sim2real-behav-cc-noqueue-")
    # Well-formed queue URL for this account/region, but no such queue exists.
    identifier = f"{sqs.meta.endpoint_url}/{account_id}/{queue_name}"

    # The synchronous call itself must raise -- UpdateResource rejects a
    # nonexistent identifier with ResourceNotFoundException up front, rather
    # than accepting the request and failing later in the async handler.
    try:
        cc.update_resource(
            TypeName=type_name,
            Identifier=identifier,
            PatchDocument=patch_document,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for a nonexistent queue, got {code!r}"
        )
        message = exc.response.get("Error", {}).get("Message", "")
        expected = _handler_not_found(message, _queue_not_found_detail(identifier))
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        # Cloud Control API's awsJson1_0 protocol surfaces this and other modeled
        # client errors as HTTP 400 rather than the semantic status implied by the
        # error name.
        assert status == 400, f"expected HTTP 400 for ResourceNotFoundException, got {status}"
    else:
        raise AssertionError(
            "expected UpdateResource against a nonexistent queue identifier to raise "
            "ResourceNotFoundException synchronously"
        )

    # Because the request was rejected before any async request/token was ever
    # created, no ResourceRequest for this identifier should be recorded.
    summary = _find_request_summary_for_identifier(cc, type_name, identifier)
    assert summary is None, (
        f"expected no ResourceRequest to be recorded for a synchronously-rejected "
        f"UpdateResource call, found {summary!r}"
    )


def _find_request_summary_for_identifier(cc, type_name: str, identifier: str) -> dict[str, Any] | None:
    paginator_kwargs: dict[str, Any] = {}
    while True:
        resp = cc.list_resource_requests(**paginator_kwargs)
        for summary in resp.get("ResourceRequestStatusSummaries", []):
            if summary.get("TypeName") == type_name and summary.get("Identifier") == identifier:
                return summary
        next_token = resp.get("NextToken")
        if not next_token:
            return None
        paginator_kwargs["NextToken"] = next_token


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _queue_not_found_detail(queue_url):
    return (
        "AWS::SQS::Queue Handler returned status FAILED: Resource of type 'AWS::SQS::Queue' "
        f"with identifier '{queue_url}' was not found."
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
