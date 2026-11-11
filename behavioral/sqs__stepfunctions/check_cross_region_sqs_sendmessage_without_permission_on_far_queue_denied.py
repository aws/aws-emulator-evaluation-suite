"""cross-region-sqs-sendmessage-without-permission-on-far-queue-denied."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-region-sqs-sendmessage-without-permission-on-far-queue-denied"
GROUP = "cross-region"
SERVICES = ["sqs", "stepfunctions"]

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


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
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK[:250]})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _exec_role(ctx, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfnsqs-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn cross-region sqs:sendMessage execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if statements:
        iam.put_role_policy(
            RoleName=name, PolicyName="send",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
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


def _receive_matching(ctx, far_region: str, queue_url: str, body: str, *, timeout_s: float) -> list[str]:
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


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A cross-region sqs:sendMessage task whose execution role lacks sqs:SendMessage on the
    far region's queue FAILS and delivers nothing there; a twin role holding the grant succeeds.
    """
    far_region = _other_region(ctx.region)
    far_queue = _far_queue(ctx, far_region)
    good_role = _exec_role(ctx, [
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": far_queue["arn"]}])
    bad_role = _exec_role(ctx, [])
    good_sm = _state_machine(ctx, good_role, far_queue["url"])
    bad_sm = _state_machine(ctx, bad_role, far_queue["url"])

    good_body = ctx.unique_name("sim2real-xr-ok-")
    good = _sync_execute(ctx, good_sm, good_body)
    assert good["status"] == "SUCCEEDED", (
        f"control: the role holding sqs:SendMessage on the far queue must SUCCEED; got "
        f"{good['status']!r} error={good.get('error')!r} cause={good.get('cause')!r}")
    good_returned = time.monotonic()
    delivered_good = _receive_matching(ctx, far_region, far_queue["url"], good_body, timeout_s=60.0)
    delivery_latency_s = time.monotonic() - good_returned
    assert delivered_good == [good_body], (
        f"the control execution must deliver exactly its own message; got {delivered_good!r}")

    bad_body = ctx.unique_name("sim2real-xr-denied-")
    bad = _sync_execute(ctx, bad_sm, bad_body)
    assert bad["status"] == "FAILED", (
        f"a role with no sqs:SendMessage grant on the far queue must FAIL the task; got "
        f"{bad['status']!r}")
    assert bad["error"] == "SQS.AmazonSQSException", (
        f"unexpected error for a cross-region sqs:sendMessage task with no grant: "
        f"error={bad.get('error')!r} cause={bad.get('cause')!r}")
    # SQS's denial text embeds the assumed-role session name and a per-call request id: mask
    # only those two.
    role_name = bad_role.rsplit("/", 1)[-1]
    cause = bad.get("cause") or ""
    masked_cause = re.sub(r"Request ID: [^;)]+", "Request ID: <request-id>", cause)
    masked_cause = re.sub(
        rf"assumed-role/{re.escape(role_name)}/[A-Za-z0-9=,.@_-]+ is not",
        f"assumed-role/{role_name}/<session> is not", masked_cause)
    expected_cause = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/<session> is not authorized "
        f"to perform: sqs:sendmessage on resource: {far_queue['arn']} because no identity-based "
        f"policy allows the sqs:sendmessage action (Service: AmazonSQS; Status Code: 403; "
        f"Error Code: AccessDenied; Request ID: <request-id>; Proxy: null)"
    )
    assert masked_cause == expected_cause, (
        f"the cause must be SQS's exact AccessDenied for this role and far queue; expected "
        f"{expected_cause!r}, got {cause!r}")

    # Absence is held for at least three times the control's measured delivery latency.
    window_s = max(15.0, 3.0 * delivery_latency_s)
    leaked = _receive_matching(ctx, far_region, far_queue["url"], bad_body, timeout_s=window_s)
    assert bad_body not in leaked, (
        f"the denied execution must deliver nothing to the far queue; got {leaked!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
