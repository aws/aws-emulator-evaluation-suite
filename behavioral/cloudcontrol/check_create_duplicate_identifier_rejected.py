"""create-duplicate-identifier-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-duplicate-identifier-rejected"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResource against an already-existing identifier with conflicting attributes is rejected, the
    original resource is left untouched both in Cloud Control's own view and in the native SQS queue it
    proxies to, and creating a distinctly-named queue still succeeds."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-cc-dup-")
    tags_prop = [{"Key": "sim2real", "Value": CHECK}]
    resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": queue_name, "VisibilityTimeout": 30, "Tags": tags_prop}),
    )
    event = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", event
    identifier = event["Identifier"]
    ctx.on_cleanup(lambda: _delete_and_wait(ctx, identifier))

    code, message = _mutate_error(
        ctx,
        lambda: cc.create_resource(
            TypeName="AWS::SQS::Queue",
            DesiredState=json.dumps({"QueueName": queue_name, "VisibilityTimeout": 99}),
        ),
    )
    assert code == "AlreadyExists", code
    assert message == "Queue creation failed because the queue already exists", message

    got = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert props["VisibilityTimeout"] == 30, "the rejected duplicate create leaked into the original resource"

    # Independent read at the destination: Cloud Control's own index could be faked by a target that
    # never actually provisions the underlying queue, so confirm the real SQS attribute too.
    queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    native_timeout = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]
    assert native_timeout == "30", f"the rejected duplicate create leaked into the native SQS queue: {native_timeout}"

    other_name = ctx.unique_name("sim2real-behav-cc-dup-control-")
    resp2 = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": other_name, "Tags": tags_prop})
    )
    event2 = _wait_for_progress(ctx, resp2["ProgressEvent"]["RequestToken"])
    assert event2["OperationStatus"] == "SUCCESS", event2
    control_identifier = event2["Identifier"]
    ctx.on_cleanup(lambda: _delete_and_wait(ctx, control_identifier))

    # The cleanup path deletes what this check creates but never proved the delete itself: exercise
    # it here so a target that only pretends to delete (or resurrects the identifier) is caught.
    del_resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=control_identifier)
    del_event = _wait_for_progress(ctx, del_resp["ProgressEvent"]["RequestToken"])
    assert del_event["OperationStatus"] == "SUCCESS", del_event

    try:
        cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=control_identifier)
        raise AssertionError("deleted control queue is still readable via CloudControl get_resource")
    except ClientError as e:
        got_code = e.response["Error"]["Code"]
        got_message = e.response["Error"]["Message"]
    assert got_code == "ResourceNotFoundException", got_code
    expected_got = _handler_not_found("AWS::SQS::Queue", control_identifier, got_message)
    assert got_message == expected_got, f"expected message {expected_got!r}, got {got_message!r}"

    mutate_code, mutate_message = _mutate_error(
        ctx,
        lambda: cc.update_resource(
            TypeName="AWS::SQS::Queue",
            Identifier=control_identifier,
            PatchDocument=json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 60}]),
        ),
    )
    assert mutate_code == "ResourceNotFoundException", mutate_code
    expected_mutate = _handler_not_found("AWS::SQS::Queue", control_identifier, mutate_message)
    assert mutate_message == expected_mutate, (
        f"expected message {expected_mutate!r}, got {mutate_message!r}"
    )


def _wait_for_progress(ctx, request_token, timeout_s=180.0, interval_s=2.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    event = None
    while time.monotonic() < deadline:
        event = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if event["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return event
        time.sleep(interval_s)
    raise AssertionError(f"operation did not stabilize within {timeout_s}s, last event={event}")


def _mutate_error(ctx, call_fn):
    """Invoke a create/update/delete call and return the refusal's (code, message) whether it
    surfaces synchronously (ClientError) or via an async FAILED progress event; raises if the
    mutation is accepted."""
    try:
        resp = call_fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    event = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    if event["OperationStatus"] == "FAILED":
        return event.get("ErrorCode"), event.get("StatusMessage")
    raise AssertionError(f"expected the mutation to be refused, but it reached {event!r}")


def _handler_not_found(type_name, identifier, message):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return (
        f"{type_name} Handler returned status FAILED: Resource of type '{type_name}' with "
        f"identifier '{identifier}' was not found. (HandlerErrorCode: NotFound, RequestToken: {token})"
    )


def _delete_and_wait(ctx, identifier, type_name="AWS::SQS::Queue"):
    cc = ctx.client("cloudcontrol")
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    try:
        _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RequestTokenNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
