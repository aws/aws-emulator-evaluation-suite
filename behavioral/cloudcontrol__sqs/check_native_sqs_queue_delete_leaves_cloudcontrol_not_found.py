"""native-sqs-queue-delete-leaves-cloudcontrol-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "native-sqs-queue-delete-leaves-cloudcontrol-not-found"
GROUP = "native-truth"
SERVICES = ["cloudcontrol", "sqs"]

QUEUE_TYPE = "AWS::SQS::Queue"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
VISIBILITY_TIMEOUT = 53
NON_EXISTENT_QUEUE = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A queue created with SQS's own API is visible to Cloud Control with SQS's values, and once
    SQS itself deletes it Cloud Control GetResource answers ResourceNotFoundException with the
    handler's exact not-found message, not a stale success.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations.html
    """
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-ccnat-")

    queue_url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={"VisibilityTimeout": str(VISIBILITY_TIMEOUT)},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=queue_url), *NON_EXISTENT_QUEUE[:1]))

    # SQS's CreateQueue is eventually consistent: a bounded, raising poll for a prerequisite, not
    # the subject of any assertion.
    native = _poll_until(
        lambda: _native_attributes(sqs, queue_url),
        lambda attrs: attrs is not None,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"the natively-created queue {queue_name!r} to become readable via SQS",
    )

    # ---- Cloud Control resolves a queue it never created, with SQS's own values ---------------
    described = _poll_until(
        lambda: _get_resource_or_none(cc, queue_url),
        lambda desc: desc is not None,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"Cloud Control GetResource to resolve {queue_name!r}, a queue it never created",
    )
    assert described["Identifier"] == queue_url, (
        f"GetResource echoed Identifier {described['Identifier']!r}, expected the queue URL "
        f"{queue_url!r}"
    )
    props = json.loads(described["Properties"])
    assert props.get("QueueName") == queue_name, (
        f"Cloud Control reports QueueName {props.get('QueueName')!r}, SQS reports {queue_name!r}"
    )
    assert props.get("VisibilityTimeout") == VISIBILITY_TIMEOUT, (
        f"Cloud Control reports VisibilityTimeout {props.get('VisibilityTimeout')!r}, SQS reports "
        f"{native['VisibilityTimeout']!r}"
    )
    assert props.get("Arn") == native["QueueArn"], (
        f"Cloud Control reports Arn {props.get('Arn')!r}, SQS reports {native['QueueArn']!r}"
    )

    # ---- ListResources enumerates it, paginated ---------------------------------------------
    _poll_until(
        lambda: _list_all_queue_urls(cc),
        lambda urls: queue_url in urls,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"ListResources to enumerate {queue_url!r}, a queue Cloud Control never created",
    )

    # ---- break the one thing: SQS itself deletes the queue, not Cloud Control -------------------
    sqs.delete_queue(QueueUrl=queue_url)
    gone_native = _poll_for_client_error(
        lambda: sqs.get_queue_url(QueueName=queue_name),
        timeout_s=45.0,
        interval_s=2.0,
        reason=f"SQS to report {queue_name!r} gone after its own DeleteQueue",
    )
    assert gone_native == NON_EXISTENT_QUEUE, (
        f"GetQueueUrl for the natively-deleted queue {queue_name!r} answered {gone_native!r}, "
        f"expected {NON_EXISTENT_QUEUE!r}"
    )

    # ---- the effect: Cloud Control must stop vouching for a queue SQS has deleted -------------
    cc_error = _poll_for_client_error(
        lambda: cc.get_resource(TypeName=QUEUE_TYPE, Identifier=queue_url),
        timeout_s=45.0,
        interval_s=2.0,
        reason=f"Cloud Control GetResource to report {queue_url!r} gone after the native delete",
    )
    expected_message = _handler_not_found(
        cc_error[1],
        f"AWS::SQS::Queue Handler returned status FAILED: Resource of type 'AWS::SQS::Queue' "
        f"with identifier '{queue_url}' was not found.",
    )
    assert cc_error == ("ResourceNotFoundException", expected_message), (
        f"GetResource for the natively-deleted queue {queue_url!r} answered {cc_error!r}, expected "
        f"('ResourceNotFoundException', {expected_message!r}); a target that still serves it is "
        f"over-permissive"
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


def _native_attributes(sqs, queue_url):
    try:
        return sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["VisibilityTimeout", "QueueArn"]
        )["Attributes"]
    except ClientError:
        return None


def _get_resource_or_none(cc, queue_url):
    try:
        return cc.get_resource(TypeName=QUEUE_TYPE, Identifier=queue_url)["ResourceDescription"]
    except ClientError:
        return None


def _list_all_queue_urls(cc):
    """Every identifier ListResources reports for AWS::SQS::Queue, across pages."""
    found: set[str] = set()
    kwargs = {"TypeName": QUEUE_TYPE}
    for _ in range(50):
        resp = cc.list_resources(**kwargs)
        found.update(d["Identifier"] for d in resp.get("ResourceDescriptions", []))
        token = resp.get("NextToken")
        if not token:
            return found
        kwargs["NextToken"] = token
    raise AssertionError(
        f"ListResources for {QUEUE_TYPE} still returned a NextToken after 50 pages "
        f"({len(found)} identifiers); pagination is not terminating"
    )


def _poll_for_client_error(fn, *, timeout_s, interval_s, reason):
    """Poll fn() until it raises ClientError and return its (Error.Code, Error.Message). RAISES
    when fn() is still succeeding at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {reason} and it never happened; last result {result!r}"
            )
        time.sleep(interval_s)


def _handler_not_found(message, detail):
    """Whether message is the handler's NotFound refusal; its trailing RequestToken is server-chosen."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
