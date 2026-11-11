"""description-max-length-exceeded-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "description-max-length-exceeded-rejected"
GROUP = "representation"
SERVICES = ["pipes"]

_TRANSITIONAL = {"CREATING", "UPDATING", "DELETING", "STARTING", "STOPPING"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePipe rejects a Description over the 512-char limit; a 512-char description succeeds."""
    source_url, source_arn = _create_queue(ctx, "sim2real-pipes-src-")
    _, target_arn = _create_queue(ctx, "sim2real-pipes-tgt-")
    role_arn = _create_pipe_role(ctx, source_arn, target_arn)

    pipes = ctx.client("pipes")
    res_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes"}

    # Positive control first: exactly at the 512-char limit succeeds, proving the account
    # and role are otherwise healthy so the rejection below is attributable to length alone.
    ok_name = ctx.unique_name("sim2real-pipes-atlimit-")
    ok_description = "y" * 512
    _create_pipe_with_retry(
        ctx,
        Name=ok_name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        Description=ok_description,
        DesiredState="STOPPED",
        Tags=res_tags,
    )
    ctx.on_cleanup(lambda: pipes.delete_pipe(Name=ok_name))
    _wait_pipe_stable(ctx, ok_name)
    described = pipes.describe_pipe(Name=ok_name)
    assert described["Description"] == ok_description, (
        f"expected Description {ok_description!r} at the 512-char limit, got {described['Description']!r}"
    )

    # Break exactly one thing: Description one character over the documented 512-char max.
    over_limit_name = ctx.unique_name("sim2real-pipes-toolong-")
    over_limit_description = "x" * 513

    code, message = _error_code(
        lambda: pipes.create_pipe(
            Name=over_limit_name,
            Source=source_arn,
            Target=target_arn,
            RoleArn=role_arn,
            Description=over_limit_description,
            DesiredState="STOPPED",
            Tags=res_tags,
        ),
        on_success="a 513-char Description should be rejected but CreatePipe succeeded",
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    expected_message = (
        f'[string "{over_limit_description}" is too long (length: 513, maximum allowed: 512)]'
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the over-limit pipe was never created.
    not_found_code, not_found_message = _error_code(
        lambda: pipes.describe_pipe(Name=over_limit_name),
        on_success="the rejected over-limit pipe should not exist but describe_pipe succeeded",
    )
    assert not_found_code == "NotFoundException", (
        f"over-limit pipe should not exist, describe_pipe returned {not_found_code!r}"
    )
    expected_not_found = f"Pipe {over_limit_name} does not exist."
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )


def _error_code(fn, *, on_success):
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"{on_success}: {result!r}")


def _create_pipe_with_retry(ctx, timeout_s=60.0, **kwargs):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume" in message.lower():
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"pipe {kwargs.get('Name')!r} still not creatable after {timeout_s}s: {last_exc}")


def _create_queue(ctx, prefix):
    sqs = ctx.client("sqs")
    tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pipes"}
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=tags)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipe_role(ctx, source_arn, target_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-pipes"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = "pipe-access"
    policy_doc = {
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
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_pipe_stable(ctx, name, timeout_s=90.0, interval_s=3.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pipes.describe_pipe(Name=name)
        if last["CurrentState"] not in _TRANSITIONAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"pipe {name} did not stabilize within {timeout_s}s "
        f"(last state {last['CurrentState'] if last else None})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
