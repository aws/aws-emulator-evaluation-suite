"""cloudcontrol-patch-remove-restores-the-native-sqs-default."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-patch-remove-restores-the-native-sqs-default"
GROUP = "native-truth"
SERVICES = ["cloudcontrol", "sqs"]

QUEUE_TYPE = "AWS::SQS::Queue"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
SET_DELAY = 60
# SQS's documented default for DelaySeconds. A fixed API constant, identical in every account and
# not raisable through Service Quotas, so pinning it is part of the contract.
DEFAULT_DELAY = 0
RESET_DELAY = 30


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Cloud Control JSON-Patch `remove` of /DelaySeconds returns the live SQS queue to its
    default 0 rather than the last-set 60, and a re-add to 30 applies, as read through SQS itself.
    """
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-ccdflt-")

    created = cc.create_resource(
        TypeName=QUEUE_TYPE,
        DesiredState=json.dumps(
            {
                "QueueName": queue_name,
                "DelaySeconds": SET_DELAY,
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ),
    )
    # Registered before the first assertion: a FAILED terminal event can still have left a real
    # queue behind, and the reapable handle is the SQS name.
    ctx.on_cleanup(lambda: _delete_queue_by_name_quiet(sqs, queue_name))
    create_event = _wait_terminal(cc, created["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", (
        f"create did not succeed: status {create_event['OperationStatus']!r}, ErrorCode "
        f"{create_event.get('ErrorCode')!r}, StatusMessage "
        f"{create_event.get('StatusMessage')!r}"
    )
    queue_url = create_event["Identifier"]

    # ---- state 1: the desired state's explicit value, read at SQS -----------------------------
    set_attrs = _attributes(sqs, queue_url, ["DelaySeconds"])
    assert set_attrs["DelaySeconds"] == str(SET_DELAY), (
        f"SQS reports DelaySeconds {set_attrs['DelaySeconds']!r} after a create that asked for "
        f"{SET_DELAY}, expected {str(SET_DELAY)!r}; the baseline for the remove is not established"
    )

    # ---- state 2: THE CLAIM -- remove restores the service's own default ----------------------
    # A target that only deletes the key from its stored model still looks right on GetResource.
    removed_event = _patch(cc, queue_url, {"op": "remove", "path": "/DelaySeconds"})
    assert removed_event["OperationStatus"] == "SUCCESS", (
        f"the remove patch terminated {removed_event['OperationStatus']!r} with ErrorCode "
        f"{removed_event.get('ErrorCode')!r} / StatusMessage "
        f"{removed_event.get('StatusMessage')!r}, expected SUCCESS"
    )
    default_attrs = _attributes(sqs, queue_url, ["DelaySeconds"])
    assert default_attrs["DelaySeconds"] == str(DEFAULT_DELAY), (
        f"after removing /DelaySeconds, SQS reports DelaySeconds "
        f"{default_attrs['DelaySeconds']!r}, expected SQS's own default {str(DEFAULT_DELAY)!r}; a "
        f"target that deletes the property from its stored model leaves the queue at "
        f"{str(SET_DELAY)!r} and every message delayed a minute"
    )

    # ---- state 3: the re-add, so the middle observation cannot be a coincidence ----------------
    readded_event = _patch(
        cc, queue_url, {"op": "add", "path": "/DelaySeconds", "value": RESET_DELAY}
    )
    assert readded_event["OperationStatus"] == "SUCCESS", (
        f"re-adding /DelaySeconds terminated {readded_event['OperationStatus']!r} with ErrorCode "
        f"{readded_event.get('ErrorCode')!r}, expected SUCCESS; a removed optional property must "
        f"be settable again"
    )
    final_attrs = _attributes(sqs, queue_url, ["DelaySeconds"])
    assert final_attrs["DelaySeconds"] == str(RESET_DELAY), (
        f"after re-adding /DelaySeconds={RESET_DELAY}, SQS reports "
        f"{final_attrs['DelaySeconds']!r}, expected {str(RESET_DELAY)!r}"
    )

    # ---- the two services must agree about the end state -------------------------------------
    props = json.loads(
        cc.get_resource(TypeName=QUEUE_TYPE, Identifier=queue_url)["ResourceDescription"][
            "Properties"
        ]
    )
    assert props.get("DelaySeconds") == RESET_DELAY, (
        f"Cloud Control reports DelaySeconds {props.get('DelaySeconds')!r} while SQS reports "
        f"{final_attrs['DelaySeconds']!r}; after a remove-then-add round trip the two views must "
        f"describe one queue"
    )
    assert props.get("QueueName") == queue_name, (
        f"Cloud Control reports QueueName {props.get('QueueName')!r}, expected {queue_name!r}"
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


def _patch(cc, queue_url, operation):
    """One JSON-Patch operation, polled to a terminal ProgressEvent."""
    resp = cc.update_resource(
        TypeName=QUEUE_TYPE,
        Identifier=queue_url,
        PatchDocument=json.dumps([operation]),
    )
    return _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])


def _attributes(sqs, queue_url, names):
    """SQS's own view, through a different operation than the one that mutated. Hard-subscripted by
    every caller so a missing attribute fails loudly rather than defaulting to the answer."""
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=names)["Attributes"]


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
