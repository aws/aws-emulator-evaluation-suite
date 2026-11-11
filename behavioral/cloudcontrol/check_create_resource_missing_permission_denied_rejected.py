"""create-resource-missing-permission-denied-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-resource-missing-permission-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResource via a RoleArn that lacks the downstream service permission fails
    FAILED/AccessDenied (not silently accepted, not a generic/unclassified failure)."""
    iam = ctx.client("iam")
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    role_name = ctx.unique_name("sim2real-behav-ccrole-")
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
    # The role has no attached/inline policies at all -> any downstream call it
    # makes (e.g. sqs:CreateQueue) is denied.

    queue_name = ctx.unique_name("sim2real-behav-ccq-")
    desired_state = json.dumps({"QueueName": queue_name})

    # IAM role trust can lag briefly before it is assumable by CloudFormation;
    # retry only on that specific transient error (freshly-created role not yet
    # visible to STS AssumeRole, or Cloud Control not yet able to assume it).
    progress = None
    deadline = time.monotonic() + 120.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            progress = cc.create_resource(
                TypeName="AWS::SQS::Queue", DesiredState=desired_state, RoleArn=role_arn
            )["ProgressEvent"]
            break
        except botocore.exceptions.ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            transient = code == "InvalidCredentialsException" or (
                code == "AccessDeniedException" and "Unable to assume role" in msg
            )
            if not transient:
                raise
            time.sleep(4.0)
    assert progress is not None, f"CreateResource never accepted the request: {last_err}"

    def _cleanup_queue() -> None:
        try:
            url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
            sqs.delete_queue(QueueUrl=url)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "AWS.SimpleQueueService.NonExistentQueue",
                "QueueDoesNotExist",
            ):
                raise

    ctx.on_cleanup(_cleanup_queue)

    final = _poll_request_status(ctx, progress["RequestToken"])
    assert final["OperationStatus"] == "FAILED", f"unexpected final status: {final}"
    assert final["ErrorCode"] == "AccessDenied", f"unexpected ErrorCode: {final}"
    # message varies: StatusMessage embeds the downstream SQS Request ID

    # Effect absent: the queue was never actually created by the crippled role.
    code, message = _error(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected the queue to not exist (NonExistentQueue) after the denied create, "
        f"got error code {code!r}"
    )
    expected_message = "The specified queue does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the identical create, using the caller's own (permitted)
    # credentials instead of the crippled role, succeeds.
    control_name = ctx.unique_name("sim2real-behav-ccq-ctl-")
    control = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": control_name})
    )["ProgressEvent"]
    ctx.on_cleanup(
        lambda: sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=control_name)["QueueUrl"])
    )
    control_final = _poll_request_status(ctx, control["RequestToken"])
    assert control_final["OperationStatus"] == "SUCCESS", (
        f"control create using the caller's own (permitted) credentials did not succeed: "
        f"{control_final}"
    )


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises -- an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_request_status(ctx, token, timeout_s=180.0, interval_s=3.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached a terminal status; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
