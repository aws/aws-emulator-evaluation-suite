"""e2e-cancel-request-mid-flight-resource-absent."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-cancel-request-mid-flight-resource-absent"
GROUP = "e2e"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A create cancelled at once ends CANCEL_COMPLETE or SUCCESS, never FAILED, and GetResource,
    ListResources and SNS agree on whether its topic exists; a cancel after SUCCESS is refused.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_CancelResourceRequest.html
    """
    cc = ctx.client("cloudcontrol")
    sns = ctx.client("sns")
    type_name = "AWS::SNS::Topic"
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Whether the cancel lands before the handler creates the topic is a race; Cloud Control does
    # not roll back work already done, so each outcome is graded by the reads agreeing with it.
    topic_name = ctx.unique_name("sim2real-behav-cc-cxl-")
    topic_arn = f"arn:aws:sns:{ctx.region}:{account_id}:{topic_name}"
    ctx.on_cleanup(lambda: _delete_and_wait(cc, type_name, topic_arn))
    desired_state = json.dumps({"TopicName": topic_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]})
    token = cc.create_resource(TypeName=type_name, DesiredState=desired_state)["ProgressEvent"]["RequestToken"]
    try:
        cc.cancel_resource_request(RequestToken=token)
    except ClientError as exc:
        # Only a request still PENDING or IN_PROGRESS can be cancelled; one that already ended
        # is refused, and the terminal status below says which way the race went.
        if not _ended_refusal(exc.response["Error"], token):
            raise
    final = _wait_terminal(cc, cc.get_resource_request_status(RequestToken=token)["ProgressEvent"])
    status = final["OperationStatus"]
    assert status in ("CANCEL_COMPLETE", "SUCCESS"), (
        f"a create cancelled at once must end CANCEL_COMPLETE or SUCCESS, got {final!r}"
    )

    exists = _sns_topic_exists(sns, topic_arn)
    assert exists or status == "CANCEL_COMPLETE", (
        f"the create ended SUCCESS, yet SNS reports no topic {topic_arn!r}"
    )
    assert _get_resource_exists(cc, type_name, topic_arn) == exists, (
        f"GetResource disagrees with SNS on whether {topic_arn!r} exists (SNS: {exists}) after "
        f"the request ended {status}"
    )
    listed = _poll_until(
        lambda: _list_contains(cc, type_name, topic_arn),
        lambda present: present is exists,
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert listed is exists, (
        f"ListResources disagrees with SNS on whether {topic_arn!r} exists (SNS: {exists})"
    )

    # Positive control: an uncancelled create is observable through the same three reads, and a
    # cancel of its finished request is refused and changes nothing.
    control_name = ctx.unique_name("sim2real-behav-cc-cxl-ctrl-")
    control_state = json.dumps(
        {"TopicName": control_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    )
    control_event = _wait_terminal(
        cc, cc.create_resource(TypeName=type_name, DesiredState=control_state)["ProgressEvent"]
    )
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"expected the positive-control create to reach SUCCESS, got {control_event!r}"
    )
    control_id = control_event["Identifier"]
    ctx.on_cleanup(lambda: _delete_and_wait(cc, type_name, control_id))

    control_token = control_event["RequestToken"]
    code, message = _error(lambda: cc.cancel_resource_request(RequestToken=control_token))
    assert (code, message) == ("ValidationException", f"Request {control_token} is already in status SUCCESS"), (
        f"CancelResourceRequest of a request that already ended SUCCESS must be refused "
        f"ValidationException 'Request {control_token} is already in status SUCCESS', got {code!r} {message!r}"
    )
    after = cc.get_resource_request_status(RequestToken=control_token)["ProgressEvent"]
    assert after["OperationStatus"] == "SUCCESS", (
        f"a refused cancel must leave the finished request SUCCESS, got {after!r}"
    )

    got = cc.get_resource(TypeName=type_name, Identifier=control_id)
    assert got["ResourceDescription"]["Identifier"] == control_id, (
        f"expected GetResource to echo identifier {control_id!r}, got {got!r}"
    )
    assert _list_contains(cc, type_name, control_id), (
        f"expected the uncancelled control topic {control_id!r} to appear in ListResources"
    )
    native_attrs = sns.get_topic_attributes(TopicArn=control_id)["Attributes"]
    assert native_attrs["TopicArn"] == control_id, (
        f"expected the native SNS GetTopicAttributes to report TopicArn {control_id!r}, "
        f"got {native_attrs.get('TopicArn')!r}"
    )


def _sns_topic_exists(sns, topic_arn: str) -> bool:
    """Whether SNS itself holds the topic: GetTopicAttributes answers, or refuses NotFound."""
    try:
        sns.get_topic_attributes(TopicArn=topic_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFound":
            return False
        raise
    return True


def _get_resource_exists(cc, type_name: str, identifier: str) -> bool:
    """Whether Cloud Control GetResource finds the resource, or refuses ResourceNotFoundException."""
    try:
        cc.get_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return True


def _ended_refusal(error: dict, token: str) -> bool:
    """Whether a cancel was refused because the request had already reached a terminal status."""
    return error.get("Code") == "ValidationException" and str(error.get("Message", "")).startswith(
        f"Request {token} is already in status "
    )


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
    while status in ("PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"):
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
    """The first probe() result that satisfies predicate, else the last one seen at the deadline."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last) and time.monotonic() < deadline:
        time.sleep(interval_s)
        last = probe()
    return last


def _delete_and_wait(cc, type_name: str, identifier: str) -> None:
    """Delete and wait; an already-gone resource is fine, any other outcome raises."""
    if not _get_resource_exists(cc, type_name, identifier):
        return
    final = _wait_terminal(cc, cc.delete_resource(TypeName=type_name, Identifier=identifier)["ProgressEvent"])
    if final["OperationStatus"] != "SUCCESS" and final.get("ErrorCode") != "NotFound":
        raise AssertionError(f"deleting {identifier} ended {final['OperationStatus']}: {final}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
