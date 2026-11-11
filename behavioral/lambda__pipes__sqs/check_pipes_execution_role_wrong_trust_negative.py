"""pipes-execution-role-wrong-trust-negative."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipes-execution-role-wrong-trust-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "pipes", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe whose role trusts lambda.amazonaws.com instead of pipes.amazonaws.com settles in
    CREATE_FAILED with a reason and relays nothing (the message stays on the source), while the same
    pipe with the correct trust runs and relays."""
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    pipes = ctx.client("pipes")

    # --- broken: role trusts lambda.amazonaws.com, not pipes.amazonaws.com ---
    bad_source_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-badpipe-src-"), tags=_resource_tags("sim2real-badpipe")
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=bad_source_url))
    bad_source_arn = sqs.get_queue_attributes(
        QueueUrl=bad_source_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    bad_target_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-badpipe-tgt-"), tags=_resource_tags("sim2real-badpipe")
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=bad_target_url))
    bad_target_arn = sqs.get_queue_attributes(
        QueueUrl=bad_target_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    bad_role_name = ctx.unique_name("sim2real-badpipe-role-")
    bad_role = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("lambda.amazonaws.com")),
        Tags=_resource_tags_kv("sim2real-badpipe"),
    )
    bad_role_arn = bad_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))

    bad_policy_name = ctx.unique_name("sim2real-badpipe-policy-")
    iam.put_role_policy(
        RoleName=bad_role_name,
        PolicyName=bad_policy_name,
        PolicyDocument=json.dumps(_pipe_permissions(bad_source_arn, bad_target_arn)),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=bad_role_name, PolicyName=bad_policy_name))

    bad_pipe_name = ctx.unique_name("sim2real-badpipe-")
    _create_pipe_with_retry(
        pipes,
        Name=bad_pipe_name,
        RoleArn=bad_role_arn,
        Source=bad_source_arn,
        Target=bad_target_arn,
        Tags=_resource_tags("sim2real-badpipe"),
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=bad_pipe_name))

    bad_final_state = _poll_until(
        lambda: pipes.describe_pipe(Name=bad_pipe_name)["CurrentState"],
        lambda state: state in ("RUNNING", "CREATE_FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert bad_final_state == "CREATE_FAILED", f"expected CREATE_FAILED, got {bad_final_state}"
    reason = pipes.describe_pipe(Name=bad_pipe_name).get("StateReason", "")
    assert reason, "expected a non-empty StateReason explaining the failure"

    marker = f"badpipe-marker-{uuid.uuid4().hex}"
    sqs.send_message(QueueUrl=bad_source_url, MessageBody=marker)
    delivered = _poll_for_marker(sqs, bad_target_url, marker, timeout_s=20)
    assert not delivered, "message was relayed even though the pipe role can't be assumed"
    still_on_source = _poll_for_marker(sqs, bad_source_url, marker, timeout_s=20)
    assert still_on_source, "message disappeared from the source queue despite the failed pipe"

    # --- positive control: identical setup with the correct trust principal ---
    good_source_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-goodpipe-src-"), tags=_resource_tags("sim2real-goodpipe")
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=good_source_url))
    good_source_arn = sqs.get_queue_attributes(
        QueueUrl=good_source_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    good_target_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-goodpipe-tgt-"), tags=_resource_tags("sim2real-goodpipe")
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=good_target_url))
    good_target_arn = sqs.get_queue_attributes(
        QueueUrl=good_target_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    good_role_name = ctx.unique_name("sim2real-goodpipe-role-")
    good_role = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy("pipes.amazonaws.com")),
        Tags=_resource_tags_kv("sim2real-goodpipe"),
    )
    good_role_arn = good_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))

    good_policy_name = ctx.unique_name("sim2real-goodpipe-policy-")
    iam.put_role_policy(
        RoleName=good_role_name,
        PolicyName=good_policy_name,
        PolicyDocument=json.dumps(_pipe_permissions(good_source_arn, good_target_arn)),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=good_role_name, PolicyName=good_policy_name))

    good_pipe_name = ctx.unique_name("sim2real-goodpipe-")
    _create_pipe_with_retry(
        pipes,
        Name=good_pipe_name,
        RoleArn=good_role_arn,
        Source=good_source_arn,
        Target=good_target_arn,
        Tags=_resource_tags("sim2real-goodpipe"),
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=good_pipe_name))

    good_final_state = _poll_until(
        lambda: pipes.describe_pipe(Name=good_pipe_name)["CurrentState"],
        lambda state: state in ("RUNNING", "CREATE_FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert good_final_state == "RUNNING", f"control pipe did not reach RUNNING: {good_final_state}"

    good_marker = f"goodpipe-marker-{uuid.uuid4().hex}"
    sqs.send_message(QueueUrl=good_source_url, MessageBody=good_marker)
    good_delivered = _poll_for_marker(sqs, good_target_url, good_marker, timeout_s=90)
    assert good_delivered, "control pipe never relayed the message"


_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags(prefix: str) -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": prefix}


def _resource_tags_kv(prefix: str) -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags(prefix).items()]


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
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {value!r}")


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
