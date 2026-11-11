"""cloudcontrol-lifecycle-visible-to-native-sqs-api."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-lifecycle-visible-to-native-sqs-api"

GROUP = "deployment-order"

SERVICES = ["cloudcontrol", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Cloud Control create, read, JSON-patch update and delete of an SQS queue is visible through
    the native SQS API at every step, and an out-of-range patch is refused without effect.
    """
    # Provisions directly rather than through a deploy helper, so the account guard runs here.
    ctx.verify_account_safety()
    cloudcontrol = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    queue_name = _xname(ctx, "ccq")
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, queue_name))

    desired_state = {
        "QueueName": queue_name,
        "VisibilityTimeout": 42,
        "Tags": _xsvc_tags_kv(),
    }
    created = _cloudcontrol_wait(
        ctx,
        cloudcontrol.create_resource(
            TypeName="AWS::SQS::Queue", DesiredState=json.dumps(desired_state)
        ),
        description=f"cloudcontrol create AWS::SQS::Queue {queue_name}",
    )
    assert created["OperationStatus"] == "SUCCESS", (
        f"cloudcontrol create ended {created['OperationStatus']}: "
        f"{created.get('StatusMessage')} / {created.get('ErrorCode')}"
    )

    # 1. The primary identifier of AWS::SQS::Queue is the queue URL, and it must be SQS's own.
    identifier = created["Identifier"]
    assert sqs.get_queue_url(QueueName=queue_name)["QueueUrl"] == identifier, (
        f"cloudcontrol reports identifier {identifier!r}; SQS resolves the queue name to a "
        "different URL, so the two services are not describing the same resource"
    )

    # 2. The desired state was really applied, and the queue really works.
    attributes = sqs.get_queue_attributes(
        QueueUrl=identifier, AttributeNames=["VisibilityTimeout", "QueueArn"]
    )["Attributes"]
    assert attributes["VisibilityTimeout"] == "42", (
        f"SQS reports VisibilityTimeout {attributes['VisibilityTimeout']!r}, the desired state "
        "asked for 42"
    )
    sqs.send_message(QueueUrl=identifier, MessageBody="via-cloudcontrol")
    messages = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=identifier, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=90.0,
        interval_s=2.0,
        description=f"message on cloudcontrol-created queue {queue_name}",
    )
    assert messages[0]["Body"] == "via-cloudcontrol", messages

    # 3. get_resource must project the live resource, agreeing with SQS on every field it reports.
    described = cloudcontrol.get_resource(
        TypeName="AWS::SQS::Queue", Identifier=identifier
    )["ResourceDescription"]
    assert described["Identifier"] == identifier, described
    properties = json.loads(described["Properties"])
    assert properties.get("QueueName") == queue_name, properties
    assert str(properties.get("VisibilityTimeout")) == "42", properties
    assert properties.get("Arn") == attributes["QueueArn"], (
        f"cloudcontrol reports Arn {properties.get('Arn')!r}, SQS reports "
        f"{attributes['QueueArn']!r}"
    )

    # 4. A JSON patch must change the LIVE queue, not just the cloudcontrol projection.
    updated = _cloudcontrol_wait(
        ctx,
        cloudcontrol.update_resource(
            TypeName="AWS::SQS::Queue",
            Identifier=identifier,
            PatchDocument=json.dumps(
                [{"op": "replace", "path": "/VisibilityTimeout", "value": 77}]
            ),
        ),
        description=f"cloudcontrol update {queue_name}",
    )
    assert updated["OperationStatus"] == "SUCCESS", (
        f"cloudcontrol update ended {updated['OperationStatus']}: "
        f"{updated.get('StatusMessage')} / {updated.get('ErrorCode')}"
    )
    observed = _poll_until(
        lambda: sqs.get_queue_attributes(
            QueueUrl=identifier, AttributeNames=["VisibilityTimeout"]
        )["Attributes"]["VisibilityTimeout"],
        lambda v: v == "77",
        timeout_s=120.0,
        interval_s=5.0,
        description=f"SQS VisibilityTimeout of {queue_name} becomes 77",
    )
    assert observed == "77", observed

    # 5. A patch that asks for a value outside the documented range must be refused, and must not
    #    change the live resource -- the control that proves step 4 was not a no-op writer.
    # message varies: the StatusMessage embeds the per-call SQS Request ID and SDK attempt count.
    refused_code, _ = _client_error(
        lambda: _cloudcontrol_raise_on_failure(
            ctx,
            cloudcontrol.update_resource(
                TypeName="AWS::SQS::Queue",
                Identifier=identifier,
                PatchDocument=json.dumps(
                    [{"op": "replace", "path": "/VisibilityTimeout", "value": 999999}]
                ),
            ),
            description=f"cloudcontrol invalid update {queue_name}",
        ),
        f"cloudcontrol update {queue_name} with an out-of-range VisibilityTimeout",
    )
    assert refused_code == "InvalidRequest", (
        f"cloudcontrol update {queue_name} with an out-of-range VisibilityTimeout ended "
        f"{refused_code!r}, expected 'InvalidRequest'"
    )
    assert (
        sqs.get_queue_attributes(
            QueueUrl=identifier, AttributeNames=["VisibilityTimeout"]
        )["Attributes"]["VisibilityTimeout"]
        == "77"
    ), "a rejected patch must leave the previous value in place"

    # 6. Delete must remove the queue as far as SQS is concerned.
    deleted = _cloudcontrol_wait(
        ctx,
        cloudcontrol.delete_resource(
            TypeName="AWS::SQS::Queue", Identifier=identifier
        ),
        description=f"cloudcontrol delete {queue_name}",
    )
    assert deleted["OperationStatus"] == "SUCCESS", (
        f"cloudcontrol delete ended {deleted['OperationStatus']}: "
        f"{deleted.get('StatusMessage')}"
    )
    _poll_for_client_error(
        lambda: sqs.get_queue_url(QueueName=queue_name),
        "AWS.SimpleQueueService.NonExistentQueue",
        "The specified queue does not exist.",
        f"get_queue_url {queue_name} after cloudcontrol delete",
        timeout_s=180.0,
    )
    gone_code, gone_message = _client_error(
        lambda: cloudcontrol.get_resource(
            TypeName="AWS::SQS::Queue", Identifier=identifier
        ),
        f"cloudcontrol get_resource {queue_name} after delete",
    )
    assert gone_code == "ResourceNotFoundException", (
        f"cloudcontrol get_resource {queue_name} after delete answered {gone_code!r}, expected "
        "'ResourceNotFoundException'"
    )
    assert _handler_not_found(
        gone_message,
        "AWS::SQS::Queue Handler returned status FAILED: Resource of type 'AWS::SQS::Queue' "
        f"with identifier '{identifier}' was not found.",
    ), gone_message


def _cloudcontrol_wait(ctx, response: dict, *, description: str, timeout_s=300.0) -> dict:
    """Poll a Cloud Control ProgressEvent to a terminal OperationStatus and return it."""
    cloudcontrol = ctx.client("cloudcontrol")
    event = response["ProgressEvent"]
    token = event["RequestToken"]
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    if event.get("OperationStatus") in terminal:
        return event
    return _poll_until(
        lambda: cloudcontrol.get_resource_request_status(RequestToken=token)[
            "ProgressEvent"
        ],
        lambda e: e.get("OperationStatus") in terminal,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=description,
    )


def _cloudcontrol_raise_on_failure(ctx, response: dict, *, description: str) -> dict:
    """As _cloudcontrol_wait, but a FAILED terminal state is re-raised as a ClientError.

    Cloud Control may reject a request synchronously or asynchronously; this normalises the two so
    the caller can assert one error code either way."""
    event = _cloudcontrol_wait(ctx, response, description=description)
    if event.get("OperationStatus") == "FAILED":
        raise ClientError(
            {
                "Error": {
                    "Code": event.get("ErrorCode", ""),
                    "Message": event.get("StatusMessage") or description,
                }
            },
            "GetResourceRequestStatus",
        )
    return event


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _client_error(fn, description):
    """Run fn() and return (Error.Code, Error.Message) of the ClientError it raises.

    Raises AssertionError when fn() succeeds, so an accepted call can never read as a refusal."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code", ""), error.get("Message", "")
    raise AssertionError(f"{description}: call unexpectedly succeeded")


def _handler_not_found(message, detail):
    """Whether message is the handler's NotFound refusal; its trailing RequestToken is server-chosen."""
    prefix = f"{detail} (HandlerErrorCode: NotFound, RequestToken: "
    return message.startswith(prefix) and message.endswith(")")


def _poll_for_client_error(fn, code, message, description, *, timeout_s=120.0, interval_s=5.0):
    """Poll fn() until it raises ClientError (deletions are eventual), then require exactly this
    Error.Code and Error.Message. Raises if fn() is still succeeding at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            observed = (error.get("Code", ""), error.get("Message", ""))
            assert observed == (code, message), (
                f"{description}: expected {(code, message)!r}, got {observed!r}"
            )
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: still succeeding after {timeout_s}s; expected "
                f"{(code, message)!r}"
            )
        time.sleep(interval_s)


def _delete_queue_by_name_if_present(sqs, queue_name: str) -> None:
    """Best-effort queue teardown by name; already-deleted is not an error."""
    try:
        url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in {
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        }:
            return
        raise
    sqs.delete_queue(QueueUrl=url)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
