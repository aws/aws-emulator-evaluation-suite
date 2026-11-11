"""pipes-execution-role-trusts-pipes-service-positive."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-execution-role-trusts-pipes-service-positive"
GROUP = "arn-resolution"
SERVICES = ["lambda", "pipes", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe whose execution role trusts pipes.amazonaws.com reaches RUNNING and relays a message from
    the source queue to the target queue."""
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    pipes = ctx.client("pipes")

    resource_tags = {"sim2real-managed": "true"}

    source_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-pipe-src-"), tags=resource_tags
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=source_url))
    source_arn = sqs.get_queue_attributes(
        QueueUrl=source_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    target_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-pipe-tgt-"), tags=resource_tags
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=target_url))
    target_arn = sqs.get_queue_attributes(
        QueueUrl=target_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-pipe-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("pipes.amazonaws.com")),
        Tags=[{"Key": k, "Value": v} for k, v in resource_tags.items()],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-pipe-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(_pipe_permissions(source_arn, target_arn)),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    pipe_name = ctx.unique_name("sim2real-pipe-")
    _create_pipe_with_retry(
        pipes,
        Name=pipe_name,
        RoleArn=role_arn,
        Source=source_arn,
        Target=target_arn,
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=pipe_name))

    final_state = _poll_until(
        lambda: pipes.describe_pipe(Name=pipe_name)["CurrentState"],
        lambda state: state in ("RUNNING", "CREATE_FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert final_state == "RUNNING", f"pipe did not reach RUNNING: {final_state}"

    marker = f"pipe-marker-{uuid.uuid4().hex}"
    sqs.send_message(QueueUrl=source_url, MessageBody=marker)

    delivered = _poll_for_marker(sqs, target_url, marker, timeout_s=90)
    assert delivered, f"marker {marker} never appeared on target queue"


def _trust_policy(service_principal: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _pipe_permissions(source_arn: str, target_arn: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arn,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
        ],
    }


def _create_pipe_with_retry(pipes, *, attempts: int = 10, delay_s: float = 3.0, **kwargs):
    last_err = None
    for _ in range(attempts):
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_err = e
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _poll_for_marker(sqs, queue_url: str, marker: str, *, timeout_s: float = 90.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg["Body"]:
                return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
