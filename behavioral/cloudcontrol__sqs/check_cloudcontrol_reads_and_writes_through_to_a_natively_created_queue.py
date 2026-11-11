"""cloudcontrol-reads-and-writes-through-to-a-natively-created-queue."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-reads-and-writes-through-to-a-natively-created-queue"
GROUP = "native-truth"
SERVICES = ["cloudcontrol", "sqs"]

QUEUE_TYPE = "AWS::SQS::Queue"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
NATIVE_VISIBILITY = 45
PATCHED_VISIBILITY = 75
NON_EXISTENT_QUEUE = ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.")


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Cloud Control reads and writes through to an SQS queue it never created: Get/List/Update act
    on SQS's own state, a never-created queue URL is ResourceNotFoundException, and after the
    delete SQS reports the queue as NonExistentQueue.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations.html
    """
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-ccthru-")

    # ---- a queue Cloud Control never created ---------------------------------------------------
    queue_url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={"VisibilityTimeout": str(NATIVE_VISIBILITY)},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_quiet(sqs, queue_url))

    # SQS CreateQueue is eventually consistent: a queue can take a moment to be usable by other
    # operations. Bounded, raises, and it is a prerequisite -- not the subject of any assertion.
    native = _poll_until(
        lambda: _native_attributes(sqs, queue_url, ["VisibilityTimeout", "QueueArn"]),
        lambda attrs: attrs is not None and "QueueArn" in attrs,
        timeout_s=60.0,
        interval_s=2.0,
        reason=f"the natively-created queue {queue_name!r} to become readable via SQS",
    )
    assert native["VisibilityTimeout"] == str(NATIVE_VISIBILITY), (
        f"SQS reports VisibilityTimeout {native['VisibilityTimeout']!r} for the queue this check "
        f"created natively, expected {str(NATIVE_VISIBILITY)!r}"
    )

    # ---- beat 1: GetResource resolves it and reports SQS's values ------------------------------
    described = _poll_until(
        lambda: _get_resource_or_none(cc, queue_url),
        lambda desc: desc is not None,
        timeout_s=60.0,
        interval_s=3.0,
        reason=(
            f"Cloud Control GetResource to resolve {queue_name!r}, a queue it never created "
            f"(bounded only for SQS's own eventual consistency)"
        ),
    )
    assert described["Identifier"] == queue_url, (
        f"GetResource echoed Identifier {described['Identifier']!r}, expected the queue URL "
        f"{queue_url!r}"
    )
    props = json.loads(described["Properties"])
    assert props.get("QueueName") == queue_name, (
        f"Cloud Control reports QueueName {props.get('QueueName')!r} for {queue_url!r}, SQS says "
        f"{queue_name!r}; the two services are not describing one resource"
    )
    assert props.get("VisibilityTimeout") == NATIVE_VISIBILITY, (
        f"Cloud Control reports VisibilityTimeout {props.get('VisibilityTimeout')!r} but SQS "
        f"reports {native['VisibilityTimeout']!r}; a value Cloud Control never wrote must still "
        f"be read through from the owning service"
    )
    assert props.get("Arn") == native["QueueArn"], (
        f"Cloud Control reports Arn {props.get('Arn')!r} but SQS reports "
        f"{native['QueueArn']!r}"
    )

    # ---- beat 2: ListResources enumerates it --------------------------------------------------
    # A well-formed queue URL in this same account and region that nothing ever created. It is
    # the negative subject twice over: absent from the listing here, and refused by GetResource
    # below.
    phantom_name = ctx.unique_name("sim2real-behav-ccphantom-")
    phantom_url = queue_url.rsplit("/", 1)[0] + "/" + phantom_name

    # The poll's own predicate carries the membership claim and it RAISES on timeout, so the
    # assertions that follow deliberately assert something the poll did not: that the same
    # listing does not also contain a URL nobody ever created, and that the ARN and URL agree.
    listed = _poll_until(
        lambda: _list_all_queue_urls(cc),
        lambda urls: queue_url in urls,
        timeout_s=60.0,
        interval_s=3.0,
        reason=(
            f"ListResources to enumerate {queue_url!r}, a queue Cloud Control never created "
            f"(a private index of self-created resources can never do this)"
        ),
    )
    assert phantom_url not in listed, (
        f"ListResources returned {phantom_url!r}, a queue URL nothing ever created; the listing "
        f"must enumerate real queues, not synthesise plausible ones"
    )
    assert native["QueueArn"].endswith(":" + queue_name), (
        f"SQS reports ARN {native['QueueArn']!r}, which does not end in the queue name "
        f"{queue_name!r}; the ARN and URL do not describe one queue"
    )

    # ---- beat 3: UpdateResource writes through, verified at SQS -------------------------------
    patched = cc.update_resource(
        TypeName=QUEUE_TYPE,
        Identifier=queue_url,
        PatchDocument=json.dumps(
            [{"op": "replace", "path": "/VisibilityTimeout", "value": PATCHED_VISIBILITY}]
        ),
    )
    update_event = _wait_terminal(cc, patched["ProgressEvent"]["RequestToken"])
    assert update_event["OperationStatus"] == "SUCCESS", (
        f"UpdateResource on a natively-created queue terminated "
        f"{update_event['OperationStatus']!r} with ErrorCode {update_event.get('ErrorCode')!r} / "
        f"StatusMessage {update_event.get('StatusMessage')!r}, expected SUCCESS"
    )
    after = _native_attributes(sqs, queue_url, ["VisibilityTimeout"])
    assert after["VisibilityTimeout"] == str(PATCHED_VISIBILITY), (
        f"after a Cloud Control patch SQS reports VisibilityTimeout "
        f"{after['VisibilityTimeout']!r}, expected {str(PATCHED_VISIBILITY)!r}; the patch must "
        f"reach the queue itself, not just Cloud Control's view of it"
    )

    # ---- beat 4: "reads through" is not "answers for anything" ----
    phantom_error = _client_error(
        lambda: cc.get_resource(TypeName=QUEUE_TYPE, Identifier=phantom_url)
    )
    # message varies: it embeds a server-generated RequestToken that no earlier call returns.
    assert phantom_error[0] == "ResourceNotFoundException", (
        f"GetResource for the never-created queue URL {phantom_url!r} answered "
        f"{phantom_error!r}, expected ResourceNotFoundException; a target that resolves any "
        f"well-formed URL is not reading through, it is guessing"
    )
    phantom_native = _client_error(lambda: sqs.get_queue_url(QueueName=phantom_name))
    assert phantom_native == NON_EXISTENT_QUEUE, (
        f"SQS answered {phantom_native!r} for {phantom_name!r}, expected "
        f"{NON_EXISTENT_QUEUE!r} -- the phantom must genuinely not exist"
    )

    # ---- the delete is a free negative: gone, and unusable --------------------------------
    removed = cc.delete_resource(TypeName=QUEUE_TYPE, Identifier=queue_url)
    delete_event = _wait_terminal(cc, removed["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", (
        f"DeleteResource on the natively-created queue terminated "
        f"{delete_event['OperationStatus']!r} with ErrorCode "
        f"{delete_event.get('ErrorCode')!r}, expected SUCCESS"
    )
    # SQS documents delete propagation as taking up to 60s, so this is a bounded poll with a
    # stated reason that RAISES -- not a sleep, and not an accept-set.
    gone_error = _poll_for_client_error(
        lambda: sqs.get_queue_url(QueueName=queue_name),
        timeout_s=90.0,
        interval_s=3.0,
        reason=(
            f"SQS to report {queue_name!r} gone after Cloud Control reported the delete SUCCESS "
            f"(SQS documents up to 60s of delete propagation)"
        ),
    )
    assert gone_error == NON_EXISTENT_QUEUE, (
        f"GetQueueUrl for the deleted queue {queue_name!r} answered {gone_error!r}, expected "
        f"{NON_EXISTENT_QUEUE!r}"
    )
    mutation_error = _client_error(
        lambda: sqs.set_queue_attributes(
            QueueUrl=queue_url, Attributes={"VisibilityTimeout": "10"}
        )
    )
    assert mutation_error == NON_EXISTENT_QUEUE, (
        f"a SetQueueAttributes on the deleted queue answered {mutation_error!r}, expected "
        f"{NON_EXISTENT_QUEUE!r}; the attribute write that demonstrably worked "
        f"through Cloud Control moments ago must now fail"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Bounded retry with a deadline and a stated reason. RAISES on timeout -- never returns its
    last value, which would let a never-converging target read as converged."""
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


def _native_attributes(sqs, queue_url, names):
    """SQS's own view. Returns None while the queue is not yet readable, so a caller can bound
    the wait; every assertion hard-subscripts what it needs."""
    try:
        return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=names)["Attributes"]
    except ClientError:
        return None


def _get_resource_or_none(cc, queue_url):
    try:
        return cc.get_resource(TypeName=QUEUE_TYPE, Identifier=queue_url)["ResourceDescription"]
    except ClientError:
        return None


def _list_all_queue_urls(cc):
    """Every identifier ListResources reports for AWS::SQS::Queue, across pages. The page bound
    exists so a target with a broken NextToken cannot loop forever; it raises rather than
    silently truncating, because a truncated listing would fake an absence."""
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


def _client_error(fn):
    """The (Error.Code, Error.Message) of the ClientError raised by fn(). RAISES if the call
    unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _poll_for_client_error(fn, *, timeout_s, interval_s, reason):
    """Poll fn() until it raises ClientError (an eventual-consistency window, so success is not
    yet a defect) and return its (Error.Code, Error.Message). RAISES when fn() is still
    succeeding at the deadline."""
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


def _delete_queue_quiet(sqs, queue_url):
    """Teardown, scoped to the one queue this check created."""
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
