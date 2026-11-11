"""cfn-resource-import-adopts-existing-queue-without-recreating-it."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-resource-import-adopts-existing-queue-without-recreating-it"

GROUP = "deploy_import"

SERVICES = ["cloudformation", "sqs"]


def _template(queue_name: str) -> str:
    """An IMPORT template. Every resource MUST carry DeletionPolicy Retain or the change set is
    rejected, and the declared properties must match the live resource or the imported resource
    is reported DRIFTED the instant it lands.
    """
    return json.dumps({
        "Resources": {
            "Imported": {
                "Type": "AWS::SQS::Queue",
                "DeletionPolicy": "Retain",
                "Properties": {"QueueName": queue_name, "VisibilityTimeout": 30},
            },
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IMPORT change set adopts an existing queue rather than recreating it: same URL, a message
    sent before the import is still receivable, the resource is IN_SYNC, and with DeletionPolicy
    Retain deleting the stack leaves the queue in place.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    queue_name = _xname(ctx, "imp-q")
    queue_url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={"VisibilityTimeout": "30"},
        tags={"sim2real": "cfn-resource-import"},
    )["QueueUrl"]
    # Registered immediately, and before the change set, because DeletionPolicy Retain means the
    # stack delete deliberately leaves this queue behind.
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, queue_name))

    marker = f"pre-import-{queue_name}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=marker)
    # Deliberately NOT received: it must still be there after the import.

    stack = _xname(ctx, "imp-s")
    change_set = cfn.create_change_set(
        StackName=stack,
        ChangeSetName=_xname(ctx, "imp-cs"),
        ChangeSetType="IMPORT",
        TemplateBody=_template(queue_name),
        ResourcesToImport=[{
            "ResourceType": "AWS::SQS::Queue",
            "LogicalResourceId": "Imported",
            # CreateChangeSet rejects "QueueURL" with ValidationError "Invalid resource identifier
            # for resource type AWS::SQS::Queue. Expected [QueueUrl]"; the key is per resource type.
            "ResourceIdentifier": {"QueueUrl": queue_url},
        }],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )["Id"]
    # An IMPORT change set CREATES the stack (in REVIEW_IN_PROGRESS), so the stack teardown is
    # registered here rather than after any create_stack.
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack, timeout_s=600.0))

    cs_status = _poll_until(lambda: _change_set(cfn, change_set)["Status"],
                            lambda s: s in {"CREATE_COMPLETE", "FAILED"},
                            timeout_s=300.0, interval_s=3.0,
                            description=f"IMPORT change set for {stack}")
    described = _change_set(cfn, change_set)
    assert cs_status == "CREATE_COMPLETE", (
        f"the IMPORT change set ended {cs_status!r}: {described.get('StatusReason')!r}"
    )
    changes = described["Changes"]
    assert len(changes) == 1, f"expected one change, got {changes!r}"
    assert changes[0]["ResourceChange"]["Action"] == "Import", (
        f"an IMPORT change set must describe its resource as Action Import, got {changes[0]!r}"
    )

    cfn.execute_change_set(ChangeSetName=change_set)
    status = _poll_until(lambda: _stack_status(cfn, stack),
                         lambda s: s in {"IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
                                         "IMPORT_ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "GONE"},
                         timeout_s=900.0, interval_s=5.0, description=f"import into {stack}")
    assert status == "IMPORT_COMPLETE", f"expected IMPORT_COMPLETE, got {status!r}"

    # 1. Identity survived: the adopted physical id is the URL that existed beforehand.
    imported_id = _physical_id(cfn, stack, "Imported")
    assert imported_id == queue_url, (
        f"the import replaced the resource instead of adopting it: {queue_url!r} -> "
        f"{imported_id!r}"
    )

    # 2. Contents survived, which a recreated queue with the same name would not show.
    received = _receive_one(sqs, queue_url, timeout_s=180.0)
    assert received["Body"] == marker, (
        f"the message enqueued before the import is gone, so the queue was recreated rather "
        f"than adopted: {received!r}"
    )

    # 3. A freshly imported resource whose template matches must not read as drifted.
    drift = cfn.detect_stack_resource_drift(
        StackName=stack, LogicalResourceId="Imported")["StackResourceDrift"]
    assert drift["StackResourceDriftStatus"] == "IN_SYNC", (
        f"a freshly imported resource whose template matches the live queue must be IN_SYNC, "
        f"got {drift!r}"
    )

    # 4. DeletionPolicy Retain: deleting the stack must leave the adopted queue in place.
    cfn.delete_stack(StackName=stack)
    delete_status = _poll_until(lambda: _stack_status(cfn, stack),
                                lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                                timeout_s=600.0, interval_s=5.0,
                                description=f"delete stack {stack}")
    assert delete_status in {"DELETE_COMPLETE", "GONE"}, (
        f"expected the stack delete to complete, got {delete_status!r}"
    )
    retained_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    assert retained_url == queue_url, (
        f"DeletionPolicy Retain should have left the queue behind after the stack was deleted, "
        f"but its URL changed: {queue_url!r} -> {retained_url!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _queue_url_or_none(sqs, name: str) -> str | None:
    try:
        return sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == _NO_SUCH_QUEUE:
            return None
        raise


def _delete_queue_by_name_if_present(sqs, name: str) -> None:
    """Best-effort queue teardown by name; already-deleted is not an error."""
    url = _queue_url_or_none(sqs, name)
    if url:
        sqs.delete_queue(QueueUrl=url)


def _receive_one(sqs, url: str, *, timeout_s=120.0) -> dict[str, Any]:
    """Long-poll a queue until one message arrives; return it (raises on timeout)."""
    msgs = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1,
                                    WaitTimeSeconds=20).get("Messages", []),
        bool, timeout_s=timeout_s, interval_s=1.0, description=f"a message on {url}")
    return msgs[0]


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    """The PhysicalResourceId CloudFormation currently records for a logical id."""
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id)["StackResourceDetail"]["PhysicalResourceId"]


def _change_set(cfn, change_set_id: str) -> dict[str, Any]:
    """DescribeChangeSet with its Changes paginated in."""
    out: dict[str, Any] = {}
    changes: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"ChangeSetName": change_set_id}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_change_set(**kwargs)
        out = page
        changes.extend(page.get("Changes", []))
        token = page.get("NextToken")
        if not token:
            break
    out["Changes"] = changes
    return out


def _delete_stack_and_wait(ctx, name: str, *, timeout_s=900.0) -> None:
    """Delete a stack and wait for it to go; only a not-found error is tolerated."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
        final = _poll_until(lambda: _stack_status(cfn, name),
                            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
                            timeout_s=timeout_s, interval_s=5.0,
                            description=f"delete stack {name}")
        if final == "DELETE_FAILED":
            raise RuntimeError(
                f"stack {name} ended DELETE_FAILED — its resources are stranded"
            )
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"stack {name} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
