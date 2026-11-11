"""iam-role-trust-sqs-service-assume."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trust-sqs-service-assume"
GROUP = "trust-policy"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Credentials from assuming a role that trusts the caller can redrive a DLQ message.
    SQS never assumes a customer role itself; the trust boundary is sts:AssumeRole, and only the
    assumed-role credentials call StartMessageMoveTask, verified by the message on the main queue."""
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    caller_arn = sts.get_caller_identity()["Arn"]

    main_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-redrive-main-"), tags=_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=main_url))
    main_arn = _queue_arn(sqs, main_url)

    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-redrive-dlq-"), tags=_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = _queue_arn(sqs, dlq_url)

    # StartMessageMoveTask only accepts a SourceArn configured as another queue's DLQ.
    sqs.set_queue_attributes(
        QueueUrl=main_url,
        Attributes={
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "1"})
        },
    )

    role_name = ctx.unique_name("sim2real-behav-redrive-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc_for_principal(caller_arn)),
        Tags=_resource_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="redrive",
        PolicyDocument=json.dumps(_redrive_policy_doc([main_arn, dlq_arn])),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="redrive"))

    body = f"redrive-payload-{role_name}"
    sqs.send_message(QueueUrl=dlq_url, MessageBody=body)

    creds = _assume_role_with_retry(sts, role_arn, "redrive-session")
    assumed_sqs = ctx.client(
        "sqs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    _start_move_task_with_retry(assumed_sqs, dlq_arn, main_arn)
    _wait_for_move_task_completion(sqs, dlq_arn)

    received = _wait_for_message_body(sqs, main_url, body, timeout_s=120.0)
    assert received == body, f"redriven message body missing or mismatched: {received!r}"


def _resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-redrive"}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _trust_doc_for_principal(principal_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": principal_arn}, "Action": "sts:AssumeRole"}
        ],
    }


def _redrive_policy_doc(queue_arns: list[str]) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "sqs:StartMessageMoveTask",
                    "sqs:SendMessage",
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                ],
                "Resource": queue_arns,
            }
        ],
    }


def _queue_arn(sqs, queue_url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]


def _assume_role_with_retry(
    sts, role_arn: str, session_name: str, timeout_s: float = 60.0, interval_s: float = 3.0
) -> dict[str, Any]:
    """A freshly created role's trust policy is eventually consistent; poll
    while STS still denies the assumption, until it actually succeeds."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "AccessDenied":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"role was never assumable within {timeout_s}s: {last_err}")


def _start_move_task_with_retry(
    assumed_sqs, source_arn: str, destination_arn: str, timeout_s: float = 60.0, interval_s: float = 3.0
) -> str:
    """The freshly attached identity policy on the role is also eventually
    consistent; poll until the assumed-role credentials are actually usable."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return assumed_sqs.start_message_move_task(
                SourceArn=source_arn, DestinationArn=destination_arn
            )["TaskHandle"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "AccessDenied":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"StartMessageMoveTask never succeeded within {timeout_s}s: {last_err}")


def _wait_for_move_task_completion(
    sqs, source_arn: str, timeout_s: float = 120.0, interval_s: float = 5.0
) -> dict[str, Any]:
    """StartMessageMoveTask runs asynchronously; poll ListMessageMoveTasks
    until the task reaches a terminal state before checking the destination
    queue for the moved message."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = sqs.list_message_move_tasks(SourceArn=source_arn, MaxResults=1)
        tasks = resp.get("Results", [])
        if tasks:
            last_status = tasks[0].get("Status")
            if last_status == "COMPLETED":
                return tasks[0]
            if last_status in ("CANCELLED", "FAILED"):
                raise AssertionError(f"move task ended with status {last_status}: {tasks[0]}")
        time.sleep(interval_s)
    raise AssertionError(f"move task did not complete within {timeout_s}s; last status={last_status}")


def _wait_for_message_body(
    sqs, queue_url: str, expected_body: str, timeout_s: float = 90.0, interval_s: float = 3.0
) -> str | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if msg["Body"] == expected_body:
                return msg["Body"]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
