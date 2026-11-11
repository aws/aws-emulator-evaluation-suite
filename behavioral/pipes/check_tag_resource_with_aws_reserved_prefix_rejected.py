"""tag-resource-with-aws-reserved-prefix-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-with-aws-reserved-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with an 'aws:'-prefixed key (reserved for AWS) is rejected with
    BadRequestException (not the modeled ValidationException) and never lands; a normal tag
    on the same pipe is applied."""
    name, arn = _build_pipe_for_tagging(ctx)
    pipes = ctx.client("pipes")

    code, message = _error(lambda: pipes.tag_resource(resourceArn=arn, tags={"aws:reserved-probe": "x"}))
    assert code == "BadRequestException", f"code={code!r}"
    assert message == "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)", (
        f"unexpected TagResource message {message!r}"
    )

    # effect absent: the reserved-prefix tag was not applied
    tags = pipes.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "aws:reserved-probe" not in tags, f"rejected tag landed anyway: tags={tags!r}"

    # positive control: a normal tag on the same pipe succeeds
    pipes.tag_resource(resourceArn=arn, tags={"team": "sim2real"})
    tags = pipes.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("team") == "sim2real", f"expected team=sim2real, got tags={tags!r}"


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _create_pipe(ctx, name, source_arn, target_arn, role_arn, desired_state="STOPPED", timeout_s=90.0, interval_s=5.0):
    # IAM role-trust propagation lag: a freshly created role/policy is not always immediately
    # visible to Pipes, so CreatePipe is retried on the transient rejection rather than slept past.
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    resp = None
    last_err = None
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
            code = err.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if resp is None:
        raise AssertionError(f"create_pipe never succeeded (role propagation?): {last_err}")
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
