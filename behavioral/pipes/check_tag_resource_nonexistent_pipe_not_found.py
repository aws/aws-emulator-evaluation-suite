"""tag-resource-nonexistent-pipe-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-pipe-not-found"
GROUP = "error-semantics"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against a non-existent pipe ARN returns NotFoundException, while
    TagResource against a real pipe (positive control, in the same file) succeeds."""
    pipes = ctx.client("pipes")
    ghost_arn = _fake_pipe_arn(ctx)

    code, message = _error(lambda: pipes.tag_resource(resourceArn=ghost_arn, tags={"env": "ghost"}))
    assert code == "NotFoundException", f"expected NotFoundException tagging a non-existent pipe, got {code!r}"
    assert message == "Resource was not found", f"unexpected TagResource message {message!r}"

    # positive control: tagging a real pipe succeeds
    name, arn = _build_pipe_for_tagging(ctx)
    pipes.tag_resource(resourceArn=arn, tags={"env": "real"})
    tags = pipes.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("env") == "real", f"expected tag env=real on the positive-control pipe, got {tags!r}"


_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_RES_TAGS_KV = [{"Key": k, "Value": v} for k, v in _RES_TAGS.items()]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what real AWS refuses fails loudly instead of
    reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _fake_pipe_arn(ctx):
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:pipes:{ctx.region}:{account_id}:pipe/{ctx.unique_name('sim2real-behav-ghost-')}"


def _create_sqs_queue(ctx, tag):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-behav-{tag}-")
    url = sqs.create_queue(QueueName=name, tags=_RES_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_pipes_role(ctx, with_permissions=True):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "pipes.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_RES_TAGS_KV,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if with_permissions:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:SendMessage"],
                "Resource": "*",
            }],
        }
        policy_name = ctx.unique_name("sim2real-behav-pipes-policy-")
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _safe_delete_pipe(ctx, name):
    pipes = ctx.client("pipes")
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_pipe(ctx, name, source_arn, target_arn, role_arn, desired_state="STOPPED"):
    pipes = ctx.client("pipes")
    # CreatePipe validates RoleArn synchronously against a role that may not have
    # propagated through IAM yet; retry on that specific rejection instead of guessing
    # a fixed wait, bounded by a deadline so a genuine, non-propagation failure still
    # raises promptly.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            resp = pipes.create_pipe(
                Name=name,
                Source=source_arn,
                SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
                Target=target_arn,
                RoleArn=role_arn,
                DesiredState=desired_state,
                Tags=_RES_TAGS,
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            retryable = code == "ValidationException" and "assume" in msg.lower()
            if not retryable:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"role {role_arn} never became assumable by pipes within 60s: {err}") from err
            time.sleep(3)
    ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, name))
    return resp["Arn"]


def _wait_for_pipe_state(ctx, name, target_states, timeout_s=240.0, interval_s=5.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    desc = None
    while time.monotonic() < deadline:
        desc = pipes.describe_pipe(Name=name)
        last = desc["CurrentState"]
        if last in target_states:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} never reached {target_states}, last state was {last}")


def _build_pipe_for_tagging(ctx):
    source = _create_sqs_queue(ctx, "src")
    target = _create_sqs_queue(ctx, "dst")
    role_arn = _create_pipes_role(ctx, with_permissions=True)
    name = ctx.unique_name("sim2real-behav-pipe-")
    arn = _create_pipe(ctx, name, source["arn"], target["arn"], role_arn, desired_state="STOPPED")
    desc = _wait_for_pipe_state(ctx, name, {"STOPPED", "CREATE_FAILED"})
    assert desc["CurrentState"] == "STOPPED", f"pipe setup failed: {desc}"
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
