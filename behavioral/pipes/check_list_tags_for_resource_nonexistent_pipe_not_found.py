"""list-tags-for-resource-nonexistent-pipe-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-pipe-not-found"
GROUP = "error-semantics"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a non-existent pipe ARN returns NotFoundException, while
    ListTagsForResource on a real pipe (positive control, in the same file) returns its tags."""
    pipes = ctx.client("pipes")
    ghost_arn = _fake_pipe_arn(ctx)

    code, message = _client_error(lambda: pipes.list_tags_for_resource(resourceArn=ghost_arn))
    assert code == "NotFoundException", f"expected NotFoundException for a never-created pipe ARN, got {code!r}"
    expected_message = "Resource was not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: listing tags on a real, tagged pipe succeeds
    name, arn = _build_pipe_for_tagging(ctx)
    pipes.tag_resource(resourceArn=arn, tags={"env": "real"})
    tags = pipes.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("env") == "real", f"expected positive-control pipe to report its own tag, got {tags!r}"


def _client_error(fn):
    """Run a call that must be refused and return its (code, message). An accepted call
    raises: an emulator accepting what real AWS refuses must fail loudly, not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _fake_pipe_arn(ctx):
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:pipes:{ctx.region}:{account_id}:pipe/{ctx.unique_name('sim2real-behav-ghost-')}"


def _create_sqs_queue(ctx, tag):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-behav-{tag}-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = pipes.create_pipe(
                Name=name,
                Source=source_arn,
                SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
                Target=target_arn,
                RoleArn=role_arn,
                DesiredState=desired_state,
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                # IAM role not yet visible to Pipes: bounded retry, not a fixed sleep.
                last_err = err
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"CreatePipe never succeeded after role propagation wait: {last_err}")
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
