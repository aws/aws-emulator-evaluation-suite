"""create-resource-access-denied-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resource-access-denied-blocked"
GROUP = "overly-permissive"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResource with a RoleArn that has no SQS permissions terminates FAILED/AccessDenied.

    No queue is created (no fallback to caller credentials); once the role is granted sqs:*,
    the identical create succeeds."""
    cc = ctx.client("cloudcontrol")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")

    role_name = ctx.unique_name("sim2real-cc-noperm-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    teardown = _Teardown()

    denied_queue_name = ctx.unique_name("sim2real-cc-denied-")
    resp = _submit_create_with_role(
        cc, "AWS::SQS::Queue", {"QueueName": denied_queue_name}, role_arn
    )
    request_token = resp["ProgressEvent"]["RequestToken"]
    ctx.on_cleanup(lambda: _cleanup_request(cc, "AWS::SQS::Queue", request_token, teardown))
    final = _poll_request_status(cc, request_token, timeout_s=90.0)

    assert final["OperationStatus"] == "FAILED", f"unexpected status: {final}"
    assert final["ErrorCode"] == "AccessDenied", f"unexpected error code: {final}"
    # message varies: StatusMessage embeds the downstream SQS Request ID

    # effect absent: the queue must not exist
    listed = sqs.list_queues(QueueNamePrefix=denied_queue_name).get("QueueUrls", [])
    assert listed == [], f"queue was created despite AccessDenied: {listed}"

    # positive control: the same operation with the caller's own (permissive) creds succeeds
    control_queue_name = ctx.unique_name("sim2real-cc-allowed-")
    control_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": control_queue_name}),
    )
    control_token = control_resp["ProgressEvent"]["RequestToken"]
    ctx.on_cleanup(lambda: _cleanup_request(cc, "AWS::SQS::Queue", control_token, teardown))
    control_final = _poll_request_status(cc, control_token, timeout_s=150.0)
    assert control_final["OperationStatus"] == "SUCCESS", f"control failed: {control_final}"

    # Grant the same role the missing permission and reissue the identical create, so the role's
    # own permissions are shown to be what gated it.
    policy_name = "sim2real-cc-sqs-create"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:*", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    restored_final = _create_with_role_until_success(
        cc, "AWS::SQS::Queue", {"QueueName": denied_queue_name}, role_arn, timeout_s=120.0
    )
    assert restored_final["OperationStatus"] == "SUCCESS", f"restore failed: {restored_final}"
    restored_identifier = restored_final["Identifier"]
    ctx.on_cleanup(
        lambda: _delete_resource(cc, "AWS::SQS::Queue", restored_identifier, teardown)
    )

    # Independent read at SQS: the once-denied queue now really exists.
    restored_url = sqs.get_queue_url(QueueName=denied_queue_name)["QueueUrl"]
    assert restored_url, f"restored queue not visible via an independent read: {restored_final}"


def _submit_create_with_role(
    cc: Any, type_name: str, desired_state: dict, role_arn: str, timeout_s: float = 90.0
) -> dict:
    """Retry CreateResource while a new role's trust policy propagates through IAM.

    Until then AssumeRole fails synchronously (AccessDeniedException "assume role" or
    InvalidCredentialsException), unlike the asynchronous handler AccessDenied under test."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return cc.create_resource(
                TypeName=type_name, DesiredState=json.dumps(desired_state), RoleArn=role_arn
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "InvalidCredentialsException" or (
                code == "AccessDeniedException" and "assume role" in message.lower()
            ):
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"role never became assumable by cloudformation.amazonaws.com: {last_exc}")


def _create_with_role_until_success(
    cc: Any, type_name: str, desired_state: dict, role_arn: str, timeout_s: float = 120.0
) -> dict:
    """Reissue the identical create while a just-granted, eventually consistent policy propagates.

    Each retry is a new request; any terminal failure other than AccessDenied raises at once."""
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        remaining = max(5.0, deadline - time.monotonic())
        resp = _submit_create_with_role(cc, type_name, desired_state, role_arn, timeout_s=remaining)
        remaining = max(5.0, deadline - time.monotonic())
        last = _poll_request_status(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=remaining)
        if last.get("OperationStatus") == "SUCCESS":
            return last
        if last.get("ErrorCode") != "AccessDenied":
            raise AssertionError(f"restore attempt failed for an unexpected reason: {last}")
        time.sleep(5.0)
    raise AssertionError(f"role never became permitted after granting sqs:CreateQueue: {last}")


def _poll_request_status(cc: Any, request_token: str, timeout_s: float = 90.0) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in terminal:
            return last
        time.sleep(2.0)
    raise AssertionError(f"request never reached a terminal state: {last}")


#: Seconds every teardown of one run shares: the suite's 900 s cleanup budget less a 120 s margin.
_CLEANUP_S = 780.0


class _Teardown:
    """One deadline for all of a run's teardowns, started when the first of them runs."""

    def __init__(self) -> None:
        self._at = None

    def deadline(self) -> float:
        if self._at is None:
            self._at = time.monotonic() + _CLEANUP_S
        return self._at


def _request_outcome(cc, token: str, teardown) -> dict:
    """Poll GetResourceRequestStatus every 2 s until the request ends; return its ProgressEvent."""
    while True:
        event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if event["OperationStatus"] not in ("PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"):
            return event
        if time.monotonic() >= teardown.deadline():
            raise AssertionError(
                f"request {token} is still {event['OperationStatus']} at the cleanup deadline"
            )
        time.sleep(2)


def _delete_resource(cc, type_name: str, identifier: str, teardown) -> None:
    """DeleteResource and wait for its outcome; a NotFound answer means the resource is gone.

    ConcurrentOperationException and ResourceConflictException (another request holds the
    resource) are retried every 2 s to the shared cleanup deadline; anything else raises."""
    while True:
        try:
            resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConcurrentOperationException", "ResourceConflictException"):
                raise
            if time.monotonic() >= teardown.deadline():
                raise
            time.sleep(2)
    event = _request_outcome(cc, resp["ProgressEvent"]["RequestToken"], teardown)
    if event["OperationStatus"] == "FAILED" and event.get("ErrorCode") == "NotFound":
        return
    if event["OperationStatus"] != "SUCCESS":
        raise AssertionError(
            f"DeleteResource of {type_name} {identifier} ended {event['OperationStatus']}: {event}"
        )


def _cleanup_request(cc, type_name: str, token: str, teardown) -> None:
    """Wait for a create request to end, then delete the resource it made."""
    event = _request_outcome(cc, token, teardown)
    if event["OperationStatus"] == "SUCCESS":
        _delete_resource(cc, type_name, event["Identifier"], teardown)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
