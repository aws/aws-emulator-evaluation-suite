"""failed-target-delivery-message-redelivered-after-visibility-timeout."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "failed-target-delivery-message-redelivered-after-visibility-timeout"
GROUP = "visibility-timeout-ttl"
SERVICES = ["pipes"]


# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """When the pipe's role lacks permission to write to the target, delivery fails,
    the source SQS message is never deleted, and it only becomes visible again for
    redelivery after its visibility timeout elapses -- not sooner."""
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")

    visibility_timeout = 10
    res_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes"}
    src_url, src_arn = _create_queue(
        ctx,
        sqs,
        ctx.unique_name("sim2real-pipes-vsrc-"),
        attributes={"VisibilityTimeout": str(visibility_timeout)},
        res_tags=res_tags,
    )
    tgt_url, tgt_arn = _create_queue(ctx, sqs, ctx.unique_name("sim2real-pipes-vtgt-"), res_tags=res_tags)

    # the role can consume the source but has NO permission on the target at all,
    # so every delivery attempt fails with an access error
    role_arn = _create_pipes_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": src_arn,
            }
        ],
        res_tags=res_tags,
    )

    name = ctx.unique_name("sim2real-pipes-vis-")
    _create_pipe_resilient(
        ctx,
        pipes,
        Name=name,
        Source=src_arn,
        Target=tgt_arn,
        RoleArn=role_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Tags=res_tags,
    )
    ctx.on_cleanup(lambda: _stop_and_delete_pipe(pipes, name))
    _wait_for_pipe_state(pipes, name, {"RUNNING"}, timeout_s=180)

    token = ctx.unique_name("probe-")
    sqs.send_message(QueueUrl=src_url, MessageBody=token)

    # Bounded wait for the pipe -- not our own probe below -- to be the one that grabs the
    # message: ApproximateNumberOfMessagesNotVisible flips to >=1 the moment *any* consumer
    # has it checked out, which for a fresh queue with no other consumer can only be the
    # pipe. Recording the wall-clock instant of pickup is what lets us assert the "not
    # sooner" half of the redelivery contract below, instead of guessing with a sleep.
    t_pickup = None
    pickup_deadline = time.monotonic() + visibility_timeout + 60
    while time.monotonic() < pickup_deadline:
        attrs = sqs.get_queue_attributes(
            QueueUrl=src_url, AttributeNames=["ApproximateNumberOfMessagesNotVisible"]
        )["Attributes"]
        if int(attrs["ApproximateNumberOfMessagesNotVisible"]) >= 1:
            t_pickup = time.monotonic()
            break
        time.sleep(1)
    assert t_pickup is not None, "pipe never picked up the source message within its poll window"

    # The target must never actually receive it (delivery is denied by IAM).
    tgt_resp = sqs.receive_message(QueueUrl=tgt_url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
    assert "Messages" not in tgt_resp, "message was delivered to the target despite missing IAM permission"

    # Stop the pipe so it stops competing with our own receive for the same message.
    pipes.stop_pipe(Name=name)
    _wait_for_pipe_state(pipes, name, {"STOPPED"}, timeout_s=120)

    # Poll for the documented condition: the message becomes receivable again by us (proof
    # via ApproximateReceiveCount that the pipe already grabbed -- and released -- it at
    # least once before our own receive).
    # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
    recovered = None
    t_recovered = None
    deadline = time.monotonic() + visibility_timeout + 90
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=src_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=2,
            AttributeNames=["ApproximateReceiveCount"],
        )
        msgs = resp.get("Messages", [])
        if msgs:
            t_recovered = time.monotonic()
            recovered = msgs[0]
            sqs.delete_message(QueueUrl=src_url, ReceiptHandle=recovered["ReceiptHandle"])
            break
        time.sleep(1)
    assert recovered is not None, "message was never receivable again after the failed target delivery"
    assert recovered["Body"] == token, "redelivered message body was corrupted"
    receive_count = int(recovered["Attributes"]["ApproximateReceiveCount"])
    assert receive_count >= 2, (
        f"ApproximateReceiveCount={receive_count}; expected >=2, proving the pipe grabbed the "
        "message at least once (and released it back on failed delivery) before our own receive"
    )

    # Time is two-sided: it must not come back BEFORE its VisibilityTimeout elapsed either.
    # The tolerance below is measurement slack (poll granularity on both ends), not a business
    # fudge -- a target that releases the message early or on a fixed short backoff instead of
    # respecting the source queue's own VisibilityTimeout must fail this.
    elapsed_since_pickup = t_recovered - t_pickup
    assert elapsed_since_pickup >= visibility_timeout - 3, (
        f"message became receivable again only {elapsed_since_pickup:.1f}s after the pipe picked "
        f"it up, before its {visibility_timeout}s VisibilityTimeout could plausibly have elapsed "
        "-- it was released too soon instead of on timeout expiry"
    )

    # And confirm the message never made it to the target because delivery kept failing.
    tgt_resp2 = sqs.receive_message(QueueUrl=tgt_url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
    assert not tgt_resp2.get("Messages"), (
        "message unexpectedly reached the target despite the execution role lacking sqs:SendMessage"
    )


def _create_queue(ctx, sqs, name, attributes=None, res_tags=None):
    kwargs = {"QueueName": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if res_tags:
        kwargs["tags"] = res_tags
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipes_role(ctx, statements, res_tags=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_kwargs = {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps(trust)}
    if res_tags:
        role_kwargs["Tags"] = [{"Key": k, "Value": v} for k, v in res_tags.items()]
    role_arn = iam.create_role(**role_kwargs)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-pipes-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _wait_for_pipe_state(pipes, name, target_states, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    desc = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in target_states:
            return desc
        if last.endswith("_FAILED"):
            raise AssertionError(f"pipe {name} entered failure state {last}: {desc.get('StateReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} did not reach {target_states} within {timeout_s}s (last={last})")


def _wait_for_pipe_deletion(pipes, name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"pipe {name} was not deleted within {timeout_s}s")


def _create_pipe_with_retry(pipes, timeout_s=90.0, interval_s=5.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            pipes.create_pipe(**kwargs)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_pipe_resilient(ctx, pipes, timeout_s=180.0, **kwargs):
    """CreatePipe, tolerating IAM role-trust propagation lag: newly created IAM
    roles/policies are not always immediately visible to other services
    (https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html)."""
    name = kwargs["Name"]
    _create_pipe_with_retry(pipes, **kwargs)
    desc = _wait_for_pipe_state(pipes, name, {"RUNNING", "STOPPED", "CREATE_FAILED"}, timeout_s=timeout_s)
    if desc["CurrentState"] == "CREATE_FAILED":
        pipes.delete_pipe(Name=name)
        _wait_for_pipe_deletion(pipes, name)
        # Retry with a longer per-attempt backoff (rather than a bare sleep) to give the
        # IAM role/policy more time to propagate before the next CreatePipe attempt.
        _create_pipe_with_retry(pipes, timeout_s=90.0, interval_s=15.0, **kwargs)
        desc = _wait_for_pipe_state(pipes, name, {"RUNNING", "STOPPED"}, timeout_s=timeout_s)
    return desc


def _stop_and_delete_pipe(pipes, name):
    try:
        pipes.stop_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    try:
        _wait_for_pipe_state(pipes, name, {"STOPPED"}, timeout_s=180)
    except AssertionError:
        pass
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
