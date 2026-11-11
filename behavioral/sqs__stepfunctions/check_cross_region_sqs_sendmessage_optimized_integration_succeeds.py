"""cross-region-sqs-sendmessage-optimized-integration-succeeds."""
from __future__ import annotations

import hashlib
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-region-sqs-sendmessage-optimized-integration-succeeds"
GROUP = "cross-region"
SERVICES = ["sqs", "stepfunctions"]

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

_MESSAGE_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _other_region(region: str) -> str:
    return "us-east-1" if region != "us-east-1" else "us-west-2"


def _definition(queue_url: str) -> str:
    return json.dumps({
        "StartAt": "SendToFarQueue",
        "States": {
            "SendToFarQueue": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage",
                "Parameters": {"QueueUrl": queue_url, "MessageBody.$": "$.body"},
                "End": True,
            },
        },
    })


def _far_queue(ctx, far_region: str) -> dict[str, str]:
    sqs = ctx.client("sqs", region=far_region)
    name = ctx.unique_name("sim2real-xsvc-sfnsqs-far-")
    url = sqs.create_queue(
        QueueName=name, tags={"sim2real": CHECK[:250]},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _exec_role(ctx, far_queue_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfnsqs-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn cross-region sqs:sendMessage execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="send",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": far_queue_arn}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="send"))
    return arn


def _state_machine(ctx, role_arn: str, queue_url: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfnsqs-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_definition(queue_url), roleArn=role_arn, type="EXPRESS",
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "security token included in the request is invalid",
)


def _sync_execute(ctx, sm_arn: str, body: str, *, deadline_s: float = 150.0) -> dict:
    """StartSyncExecution, retrying only while the role (and, for the far region, its
    cross-region propagation) has not yet taken effect."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        resp = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({"body": body}))
        cause = resp.get("cause") or ""
        if resp["status"] == "FAILED" and any(m in cause for m in _PROPAGATION_MARKERS):
            last = resp
            time.sleep(4.0)
            continue
        return resp
    raise AssertionError(f"StartSyncExecution still trust-denied after {deadline_s}s: {last}")


def _receive_matching(ctx, far_region: str, queue_url: str, body: str, *, timeout_s: float = 60.0) -> list[str]:
    sqs = ctx.client("sqs", region=far_region)
    deadline = time.monotonic() + timeout_s
    bodies: list[str] = []
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=2).get("Messages", []):
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if body in bodies:
            return bodies
        time.sleep(2.0)
    return bodies


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A states:::sqs:sendMessage task delivers to a QueueUrl in another region of the same
    account: StartSyncExecution reports SUCCEEDED with the SendMessage response, and the far
    region's own endpoint holds the message.
    """
    far_region = _other_region(ctx.region)
    far_queue = _far_queue(ctx, far_region)
    role_arn = _exec_role(ctx, far_queue["arn"])
    sm_arn = _state_machine(ctx, role_arn, far_queue["url"])

    body = ctx.unique_name("sim2real-xr-body-")
    resp = _sync_execute(ctx, sm_arn, body)
    assert resp["status"] == "SUCCEEDED", (
        f"a cross-region sqs:sendMessage task must SUCCEED; got {resp['status']!r} "
        f"error={resp.get('error')!r} cause={resp.get('cause')!r}")

    out = json.loads(resp["output"])
    assert out["MD5OfMessageBody"] == hashlib.md5(body.encode()).hexdigest(), (
        f"MD5OfMessageBody must match the body sent; got {out!r} for body {body!r}")
    assert _MESSAGE_ID_RE.match(out["MessageId"]), (
        f"MessageId must be a UUID-shaped SQS message id; got {out.get('MessageId')!r}")

    delivered = _receive_matching(ctx, far_region, far_queue["url"], body)
    assert delivered == [body], (
        f"the far-region queue must hold exactly the one message sent through the optimized "
        f"integration; got {delivered!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
