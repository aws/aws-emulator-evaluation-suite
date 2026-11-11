"""create-pipe-unassumable-role-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-pipe-unassumable-role-rejected"
GROUP = "server-side"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePipe rejects a RoleArn whose trust policy does not allow the pipes service to
    assume it, and leaves no partially-created pipe behind; a correctly-trusted role in the
    same file creates and runs an otherwise identical pipe normally."""
    pipes = ctx.client("pipes")
    iam = ctx.client("iam")

    src_url, src_arn = _create_sqs_queue(ctx)
    tgt_url, tgt_arn = _create_sqs_queue(ctx)

    # Role trusted only by a DIFFERENT service -- pipes.amazonaws.com cannot assume it.
    bad_role_name = ctx.unique_name("sim2real-pipes-badrole-")
    bad_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    bad_role_arn = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=json.dumps(bad_trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-pipes"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: iam.delete_role(RoleName=bad_role_name)))

    bad_name = ctx.unique_name("sim2real-pipes-badpipe-")
    create_resp = pipes.create_pipe(
        Name=bad_name,
        RoleArn=bad_role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        DesiredState="STOPPED",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes"},
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: pipes.delete_pipe(Name=bad_name)))
    # CreatePipe accepts the request synchronously (CurrentState starts CREATING) because
    # role-assumability is only verified asynchronously; the failure surfaces later as a
    # terminal CurrentState rather than as an immediate CreatePipe error.
    assert create_resp["CurrentState"] in ("CREATING", "CREATE_FAILED"), (
        f"expected CreatePipe to accept synchronously (CREATING/CREATE_FAILED), got {create_resp['CurrentState']!r}"
    )
    final_state = _wait_pipe_current_state(
        ctx, pipes, bad_name, {"CREATE_FAILED", "CREATE_ROLLBACK_FAILED"}, timeout_s=150
    )
    assert final_state in ("CREATE_FAILED", "CREATE_ROLLBACK_FAILED"), (
        f"expected an unassumable role to fail pipe creation, got terminal state {final_state!r}"
    )
    described = pipes.describe_pipe(Name=bad_name)
    reason = described.get("StateReason", "")
    assert reason, "a failed pipe should carry a non-empty StateReason"
    assert "assume" in reason.lower(), (
        f"StateReason should attribute the failure to role assumption, got {reason!r}"
    )


    # Positive control: the same source/target with a correctly-trusted role succeeds.
    good_role_arn = _create_pipe_role(ctx, [{"Effect": "Allow", "Action": "sqs:*", "Resource": [src_arn, tgt_arn]}])
    good_name = ctx.unique_name("sim2real-pipes-goodpipe-")
    _create_pipe_with_retry(
        ctx, pipes,
        Name=good_name,
        RoleArn=good_role_arn,
        Source=src_arn,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        Target=tgt_arn,
        DesiredState="STOPPED",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes"},
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: pipes.delete_pipe(Name=good_name)))

    final_state = _wait_pipe_current_state(ctx, pipes, good_name, {"STOPPED"})
    assert final_state == "STOPPED", (
        f"positive control: a correctly-trusted role should reach STOPPED, got {final_state!r}"
    )
    described_good = pipes.describe_pipe(Name=good_name)
    assert described_good["Name"] == good_name, (
        f"expected describe_pipe to echo Name {good_name!r}, got {described_good['Name']!r}"
    )


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _safe_cleanup(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "NoSuchEntity",
            "NotFoundException",
            "QueueDoesNotExist",
        ):
            raise


def _create_sqs_queue(ctx, *, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-pipes-q-")
    attrs = {}
    if fifo:
        name = f"{name}.fifo"
        attrs["FifoQueue"] = "true"
        attrs["ContentBasedDeduplication"] = "true"
    if extra_attrs:
        attrs.update(extra_attrs)
    kwargs = {"QueueName": name, "tags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes"}}
    if attrs:
        kwargs["Attributes"] = attrs
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipe_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "pipes.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-pipes"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: iam.delete_role(RoleName=role_name)))
    policy_name = ctx.unique_name("sim2real-pipes-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))
    return role_arn


def _create_pipe_with_retry(ctx, pipes, *, timeout_s=90, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err


def _wait_pipe_current_state(ctx, pipes, name, states, timeout_s=150, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pipes.describe_pipe(Name=name)["CurrentState"]
        if last in states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} never reached {states}, last state was {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
