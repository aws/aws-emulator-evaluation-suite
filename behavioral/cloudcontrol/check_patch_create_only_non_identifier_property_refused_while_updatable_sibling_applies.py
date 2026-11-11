"""patch-create-only-non-identifier-property-refused-while-updatable-sibling-applies."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "patch-create-only-non-identifier-property-refused-while-updatable-sibling-applies"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]

QUEUE_TYPE = "AWS::SQS::Queue"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}

# The handler error-code taxonomy Cloud Control reports on a FAILED ProgressEvent, mapped to the
# exception name the same condition carries when it is refused synchronously. The assertion pins
# ONE string, so the sync/async question cannot change the verdict.
HANDLER_ERROR_TO_EXCEPTION = {
    "AlreadyExists": "AlreadyExistsException",
    "NotFound": "ResourceNotFoundException",
    "NotUpdatable": "NotUpdatableException",
    "InvalidRequest": "InvalidRequestException",
    "ResourceConflict": "ResourceConflictException",
    "NotStabilized": "NotStabilizedException",
    "ServiceLimitExceeded": "ServiceLimitExceededException",
    "Throttling": "ThrottlingException",
    "AccessDenied": "AccessDeniedException",
    "InternalFailure": "HandlerInternalFailureException",
    "GeneralServiceException": "GeneralServiceException",
    "ServiceInternalError": "ServiceInternalErrorException",
    "NetworkFailure": "NetworkFailureException",
    "UnsupportedTarget": "UnsupportedActionException",
    "InvalidCredentials": "InvalidCredentialsException",
}

INITIAL_VISIBILITY = 30
CONTROL_VISIBILITY = 45
SURVIVAL_RETENTION = 120


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Patching the create-only, non-identifier /FifoQueue of an SQS queue is refused
    NotUpdatableException naming the property and changes nothing, while supported patches to
    /VisibilityTimeout before and /MessageRetentionPeriod after the refusal succeed.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sqs-queue.html
    """
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-cconly-")

    created = cc.create_resource(
        TypeName=QUEUE_TYPE,
        DesiredState=json.dumps(
            {
                "QueueName": queue_name,
                "VisibilityTimeout": INITIAL_VISIBILITY,
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ),
    )
    # Registered before the first assertion: a FAILED terminal event can still have left a real
    # queue behind, and the reapable handle is the SQS name, not the request token.
    ctx.on_cleanup(lambda: _delete_queue_by_name_quiet(sqs, queue_name))
    create_event = _wait_terminal(cc, created["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", (
        f"create did not succeed: status {create_event['OperationStatus']!r}, ErrorCode "
        f"{create_event.get('ErrorCode')!r}, StatusMessage "
        f"{create_event.get('StatusMessage')!r}"
    )
    queue_url = create_event["Identifier"]
    assert queue_url.endswith("/" + queue_name), (
        f"the SUCCESS event reports Identifier {queue_url!r}, which is not a URL for the queue "
        f"named {queue_name!r}"
    )

    # ---- positive control: a supported patch on the same queue ----
    control_event = _patch(cc, queue_url, "replace", "/VisibilityTimeout", CONTROL_VISIBILITY)
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"the positive control patch of /VisibilityTimeout terminated "
        f"{control_event['OperationStatus']!r} with ErrorCode "
        f"{control_event.get('ErrorCode')!r}; a supported patch must succeed, or the refusal "
        f"below proves nothing about create-only handling"
    )
    control_attrs = _attributes(sqs, queue_url, ["VisibilityTimeout"])
    assert control_attrs["VisibilityTimeout"] == str(CONTROL_VISIBILITY), (
        f"SQS reports VisibilityTimeout {control_attrs['VisibilityTimeout']!r} after the control "
        f"patch, expected {str(CONTROL_VISIBILITY)!r}"
    )

    # ---- the create-only patch is refused with the specific code ----
    # "add", not "replace": FifoQueue is absent from a standard queue's properties, and RFC 6902
    # "replace" on an absent path fails as ValidationException before the create-only check.
    refusal, refusal_message = _normalized_failure_code(
        cc,
        lambda: cc.update_resource(
            TypeName=QUEUE_TYPE,
            Identifier=queue_url,
            PatchDocument=json.dumps([{"op": "add", "path": "/FifoQueue", "value": True}]),
        ),
    )
    assert refusal == "NotUpdatableException", (
        f"patching the create-only /FifoQueue was refused with {refusal!r} ({refusal_message!r}), "
        f"expected NotUpdatableException"
    )
    assert "createOnlyProperties" in refusal_message and "FifoQueue" in refusal_message, (
        f"NotUpdatableException's message {refusal_message!r} does not name createOnlyProperties "
        f"and /properties/FifoQueue specifically; a target that refuses every patch with a generic "
        f"NotUpdatableException must not pass this check"
    )
    assert refusal_message == "Invalid patch update: createOnlyProperties [/properties/FifoQueue] cannot be updated", (
        f"unexpected NotUpdatableException message {refusal_message!r}"
    )

    # ---- the effect is absent, read at SQS ----
    # "All": naming FifoQueue explicitly on a standard queue raises InvalidAttributeName.
    after = _attributes(sqs, queue_url, ["All"])
    assert "FifoQueue" not in after, (
        f"SQS now reports FifoQueue {after.get('FifoQueue')!r} for a standard queue whose "
        f"conversion Cloud Control refused; a refused patch must change nothing"
    )
    assert after["VisibilityTimeout"] == str(CONTROL_VISIBILITY), (
        f"SQS reports VisibilityTimeout {after['VisibilityTimeout']!r} after the refused patch, "
        f"expected the control's {str(CONTROL_VISIBILITY)!r}; the refusal must not have clobbered "
        f"an unrelated property"
    )

    # ---- create-only never becomes updatable; prove the queue still accepts patches ----
    survival_event = _patch(
        cc, queue_url, "replace", "/MessageRetentionPeriod", SURVIVAL_RETENTION
    )
    assert survival_event["OperationStatus"] == "SUCCESS", (
        f"a second supported patch after the refusal terminated "
        f"{survival_event['OperationStatus']!r} with ErrorCode "
        f"{survival_event.get('ErrorCode')!r}; the refusal must not have poisoned the resource"
    )
    survived = _attributes(sqs, queue_url, ["MessageRetentionPeriod", "VisibilityTimeout"])
    assert survived["MessageRetentionPeriod"] == str(SURVIVAL_RETENTION), (
        f"SQS reports MessageRetentionPeriod {survived['MessageRetentionPeriod']!r}, expected "
        f"{str(SURVIVAL_RETENTION)!r}"
    )
    assert survived["VisibilityTimeout"] == str(CONTROL_VISIBILITY), (
        f"SQS reports VisibilityTimeout {survived['VisibilityTimeout']!r} after the third patch, "
        f"expected the untouched {str(CONTROL_VISIBILITY)!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Bounded retry with a deadline and a stated reason. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never happened; last observation {last!r}"
    )


def _wait_terminal(cc, request_token, *, timeout_s=90.0, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda event: event is not None and event["OperationStatus"] in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        reason=f"request {request_token} to reach a terminal OperationStatus",
    )


def _patch(cc, queue_url, op, path, value):
    """One JSON-Patch operation, polled to a terminal ProgressEvent."""
    resp = cc.update_resource(
        TypeName=QUEUE_TYPE,
        Identifier=queue_url,
        PatchDocument=json.dumps([{"op": op, "path": path, "value": value}]),
    )
    return _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])


def _attributes(sqs, queue_url, names):
    """SQS's own view, through a different operation than the one that mutated."""
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=names)["Attributes"]


def _normalized_failure_code(cc, call):
    """(exception-style code, message) for a call refused synchronously or via a FAILED
    ProgressEvent; raises if the call reaches a non-FAILED terminal state."""
    try:
        resp = call()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    status = event["OperationStatus"]
    if status != "FAILED":
        raise AssertionError(
            f"the patch was expected to be refused but reached {status!r}: {event!r}"
        )
    handler_code = event.get("ErrorCode")
    return HANDLER_ERROR_TO_EXCEPTION.get(handler_code, handler_code), event.get(
        "StatusMessage", ""
    )


def _delete_queue_by_name_quiet(sqs, queue_name):
    """Teardown, scoped to the one queue this check created."""
    try:
        sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=queue_name)["QueueUrl"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
