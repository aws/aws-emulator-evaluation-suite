"""iam-role-trust-mismatched-principal-sqs-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trust-mismatched-principal-sqs-blocked"
GROUP = "trust-policy"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting lambda.amazonaws.com instead of the caller cannot be assumed for an SQS redrive.
    AssumeRole is denied with the exact STS message and the DLQ message never moves; an identical
    role trusting the caller is assumed and completes the redrive (positive control)."""
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    caller_arn = sts.get_caller_identity()["Arn"]

    # Broken: the role trusts an unrelated service principal, not the caller.
    bad_main_url, bad_main_arn, bad_dlq_url, bad_dlq_arn = _make_redrive_queue_pair(ctx, sqs)
    bad_role_name = ctx.unique_name("sim2real-behav-badredrive-role-")
    bad_role_arn = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc_for_service("lambda.amazonaws.com")),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))
    iam.put_role_policy(
        RoleName=bad_role_name,
        PolicyName="redrive",
        PolicyDocument=json.dumps(_redrive_policy_doc([bad_main_arn, bad_dlq_arn])),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=bad_role_name, PolicyName="redrive"))

    bad_body = f"blocked-redrive-{bad_role_name}"
    sqs.send_message(QueueUrl=bad_dlq_url, MessageBody=bad_body)

    expected_denial = f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: {bad_role_arn}"
    code1, message1 = _client_error(lambda: sts.assume_role(RoleArn=bad_role_arn, RoleSessionName="s1"))
    assert code1 == "AccessDenied", f"got {code1}"
    assert message1 == expected_denial, f"expected message {expected_denial!r}, got {message1!r}"
    _assert_denial_persists(sts, bad_role_arn, expected_denial, session_prefix="s")

    still_on_dlq = sqs.receive_message(
        QueueUrl=bad_dlq_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
    ).get("Messages", [])
    assert any(m["Body"] == bad_body for m in still_on_dlq), "message vanished from the DLQ"
    on_main = sqs.receive_message(
        QueueUrl=bad_main_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
    ).get("Messages", [])
    assert on_main == [], f"message should never have reached the main queue, got {on_main}"

    # Positive control: same shape, the role trusts the caller.
    good_main_url, good_main_arn, good_dlq_url, good_dlq_arn = _make_redrive_queue_pair(ctx, sqs)
    good_role_name = ctx.unique_name("sim2real-behav-goodredrive-role-")
    good_role_arn = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_doc_for_principal(caller_arn)),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    iam.put_role_policy(
        RoleName=good_role_name,
        PolicyName="redrive",
        PolicyDocument=json.dumps(_redrive_policy_doc([good_main_arn, good_dlq_arn])),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=good_role_name, PolicyName="redrive"))

    good_body = f"allowed-redrive-{good_role_name}"
    sqs.send_message(QueueUrl=good_dlq_url, MessageBody=good_body)

    creds = _assume_role_with_retry(sts, good_role_arn, "redrive-control-session")
    assumed_sqs = ctx.client(
        "sqs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    _start_move_task_with_retry(assumed_sqs, good_dlq_arn, good_main_arn)
    _wait_for_move_task_completion(sqs, good_dlq_arn)

    received = _wait_for_message_body(sqs, good_main_url, good_body, timeout_s=120.0)
    assert received == good_body, f"positive control redrive failed: {received!r}"


def _trust_doc_for_principal(principal: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"}
        ],
    }


def _trust_doc_for_service(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
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


def _make_redrive_queue_pair(ctx, sqs) -> tuple[str, str, str, str]:
    main_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-redrive-main-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=main_url))
    main_arn = _queue_arn(sqs, main_url)

    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-redrive-dlq-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = _queue_arn(sqs, dlq_url)

    sqs.set_queue_attributes(
        QueueUrl=main_url,
        Attributes={
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "1"})
        },
    )
    return main_url, main_arn, dlq_url, dlq_arn


def _client_error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _assert_denial_persists(
    sts,
    role_arn: str,
    expected_message: str,
    session_prefix: str,
    attempts: int = 3,
    interval_s: float = 3.0,
) -> None:
    """A single AccessDenied could be IAM's brief eventual-consistency window right after the
    role was created, not the trust-policy decision this check exists to prove. Demand the
    identical refusal on every one of several attempts spaced across several seconds before
    treating the denial as settled."""
    for i in range(attempts):
        time.sleep(interval_s)
        code, message = _client_error(
            lambda i=i: sts.assume_role(RoleArn=role_arn, RoleSessionName=f"{session_prefix}{i + 2}")
        )
        assert code == "AccessDenied", f"attempt {i}: got {code}"
        assert message == expected_message, f"attempt {i}: expected {expected_message!r}, got {message!r}"


def _assume_role_with_retry(
    sts, role_arn: str, session_name: str, timeout_s: float = 60.0, interval_s: float = 3.0
) -> dict[str, Any]:
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
                raise AssertionError(
                    f"move task ended with status {last_status}; "
                    f"reason={tasks[0].get('FailureReason')!r}"
                )
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
