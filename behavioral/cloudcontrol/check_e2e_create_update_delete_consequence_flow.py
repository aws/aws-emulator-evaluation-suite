"""e2e-create-update-delete-consequence-flow."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-create-update-delete-consequence-flow"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create, update and delete an SQS queue via Cloud Control: each value is visible via
    GetResource and native SQS, and after delete the queue is gone from GetResource,
    ListResources and SQS, and UpdateResource is refused with ResourceNotFoundException."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    type_name = "AWS::SQS::Queue"
    queue_name = ctx.unique_name("sim2real-behav-cc-")

    desired_state = json.dumps(
        {
            "QueueName": queue_name,
            "VisibilityTimeout": 30,
            "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
        }
    )
    create_event = _wait_terminal(
        cc, cc.create_resource(TypeName=type_name, DesiredState=desired_state)["ProgressEvent"]
    )
    assert create_event["OperationStatus"] == "SUCCESS", f"create did not reach SUCCESS: {create_event}"
    identifier = create_event["Identifier"]
    assert isinstance(identifier, str) and identifier, (
        f"expected a non-empty string Identifier from CreateResource, got {identifier!r}"
    )

    ctx.on_cleanup(lambda: _delete_if_present(cc, type_name, identifier))

    # Positive control for the post-delete ListResources absence check.
    present_before = _poll_until(
        lambda: _list_contains(cc, type_name, identifier),
        lambda present: present is True,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert present_before is True, f"newly-created {identifier} never appeared in ListResources"

    got = cc.get_resource(TypeName=type_name, Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert int(props["VisibilityTimeout"]) == 30, (
        f"expected VisibilityTimeout 30 right after create, got {props.get('VisibilityTimeout')!r}"
    )

    # Read back through native SQS to prove a real queue exists.
    native_attrs = sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["VisibilityTimeout"])
    assert native_attrs["Attributes"]["VisibilityTimeout"] == "30", (
        f"native SQS reports VisibilityTimeout {native_attrs['Attributes'].get('VisibilityTimeout')!r} "
        "right after create, cloudcontrol's desired state asked for 30"
    )

    patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 60}])
    update_event = _wait_terminal(
        cc,
        cc.update_resource(
            TypeName=type_name, Identifier=identifier, PatchDocument=patch
        )["ProgressEvent"],
    )
    assert update_event["OperationStatus"] == "SUCCESS", f"update did not reach SUCCESS: {update_event}"

    got = cc.get_resource(TypeName=type_name, Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert int(props["VisibilityTimeout"]) == 60, (
        f"expected VisibilityTimeout 60 after update, got {props.get('VisibilityTimeout')!r}"
    )

    native_attrs = sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["VisibilityTimeout"])
    assert native_attrs["Attributes"]["VisibilityTimeout"] == "60", (
        f"native SQS reports VisibilityTimeout {native_attrs['Attributes'].get('VisibilityTimeout')!r} "
        "after the cloudcontrol patch asked for 60"
    )

    delete_event = _wait_terminal(
        cc, cc.delete_resource(TypeName=type_name, Identifier=identifier)["ProgressEvent"]
    )
    assert delete_event["OperationStatus"] == "SUCCESS", f"delete did not reach SUCCESS: {delete_event}"

    # message varies: the handler embeds its own per-call RequestToken, which the check never sees
    code, _ = _error(lambda: cc.get_resource(TypeName=type_name, Identifier=identifier))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetResource after delete, got {code!r}"
    )

    native_code, native_message = _error(
        lambda: sqs.get_queue_attributes(QueueUrl=identifier, AttributeNames=["VisibilityTimeout"])
    )
    assert native_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected native SQS AWS.SimpleQueueService.NonExistentQueue after cloudcontrol delete, "
        f"got {native_code!r}"
    )
    assert native_message == "The specified queue does not exist.", (
        f"expected native SQS's exact not-found message, got {native_message!r}"
    )

    # message varies: the handler embeds its own per-call RequestToken, which the check never sees
    mutate_code, _ = _error(
        lambda: cc.update_resource(
            TypeName=type_name,
            Identifier=identifier,
            PatchDocument=json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 45}]),
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"UpdateResource against a deleted identifier must be refused with ResourceNotFoundException, "
        f"got {mutate_code!r}"
    )

    present = _poll_until(
        lambda: _list_contains(cc, type_name, identifier),
        lambda present: present is False,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert present is False, f"{identifier} still appears in ListResources after delete"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) fn() is refused with; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


def _wait_terminal(cc, progress_event: dict, timeout_s: float = 120.0, interval_s: float = 2.0) -> dict:
    status = progress_event["OperationStatus"]
    token = progress_event["RequestToken"]
    deadline = time.monotonic() + timeout_s
    while status in ("PENDING", "IN_PROGRESS"):
        if time.monotonic() > deadline:
            raise AssertionError(
                f"request {token} did not reach a terminal state within {timeout_s}s, "
                f"last event={progress_event}"
            )
        time.sleep(interval_s)
        progress_event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        status = progress_event["OperationStatus"]
    return progress_event


def _list_contains(cc, type_name: str, identifier: str, max_pages: int = 200) -> bool:
    token = None
    pages = 0
    while pages < max_pages:
        kwargs: dict[str, Any] = {"TypeName": type_name, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = cc.list_resources(**kwargs)
        for desc in resp.get("ResourceDescriptions", []):
            if desc["Identifier"] == identifier:
                return True
        token = resp.get("NextToken")
        pages += 1
        if not token:
            break
    return False


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not satisfied within {timeout_s}s, last observed={last}")


def _delete_if_present(cc, type_name: str, identifier: str) -> None:
    """Delete and wait; an already-gone resource is fine, any other outcome raises."""
    try:
        cc.get_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    final = _wait_terminal(cc, cc.delete_resource(TypeName=type_name, Identifier=identifier)["ProgressEvent"])
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise AssertionError(f"deleting {identifier} ended {final['OperationStatus']}: {final}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
