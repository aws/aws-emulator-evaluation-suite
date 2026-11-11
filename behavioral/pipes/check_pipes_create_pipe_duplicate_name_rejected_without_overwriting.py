"""pipes-create-pipe-duplicate-name-rejected-without-overwriting."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-create-pipe-duplicate-name-rejected-without-overwriting"

GROUP = "rejection"

SERVICES = ["pipes"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """CreatePipe on an existing name fails with ConflictException and leaves the existing pipe's
    Description, DesiredState and SourceParameters unchanged (create is not an upsert).
    The same request under a fresh name succeeds, so the refusal is about the name collision.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/pipes-reference/API_CreatePipe.html
    """
    pipes = ctx.client("pipes")
    source = _create_queue(ctx)
    target = _create_queue(ctx)
    role = _create_pipe_role(ctx, source["arn"], target["arn"])

    original_description = "sim2real-original-description"
    collide_description = "sim2real-must-not-land"

    name = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        desired_state="STOPPED",
        wait_for="STOPPED",
        Description=original_description,
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
    )
    before = pipes.describe_pipe(Name=name)
    assert before["Description"] == original_description, (
        f"setup: the first pipe must hold its own description, got {before!r}"
    )

    # Reuse the name with every other field different, so an upsert would show in describe_pipe.
    collide_kwargs = {
        "RoleArn": role["arn"],
        "Source": source["arn"],
        "Target": target["arn"],
        "DesiredState": "RUNNING",
        "Description": collide_description,
        "SourceParameters": {"SqsQueueParameters": {"BatchSize": 7}},
    }
    code, message = _rejected_error(ctx, Name=name, **collide_kwargs)
    assert code == "ConflictException", (
        f"CreatePipe on the existing name {name!r} must be refused with ConflictException, got "
        f"{code!r}"
    )
    expected_message = f"Pipe {name} already exists."
    assert message == expected_message, (
        f"CreatePipe on the existing name {name!r}: expected message {expected_message!r}, got "
        f"{message!r}"
    )

    after = pipes.describe_pipe(Name=name)
    assert after["Description"] == original_description, (
        f"the refused CreatePipe overwrote the existing pipe's Description: expected "
        f"{original_description!r}, got {after['Description']!r} -- an upsert that raises after "
        f"mutating looks exactly like this"
    )
    assert after["DesiredState"] == "STOPPED", (
        f"the refused CreatePipe overwrote the existing pipe's DesiredState: expected 'STOPPED', "
        f"got {after['DesiredState']!r}"
    )
    assert after["SourceParameters"]["SqsQueueParameters"]["BatchSize"] == 1, (
        f"the refused CreatePipe overwrote the existing pipe's SourceParameters: expected "
        f"BatchSize 1, got {after['SourceParameters']!r}"
    )
    assert _pipe_names(ctx, name) == {name}, (
        f"exactly one pipe may carry the name {name!r} after the collision; the fully-paginated "
        f"list_pipes result under that prefix is {sorted(_pipe_names(ctx, name))!r}"
    )

    # Positive control: the same request body under a fresh name is accepted.
    control = _xname(ctx, "pipe")
    pipes.create_pipe(Name=control, Tags=_xsvc_resource_tags(), **collide_kwargs)
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=control))
    control_state = _poll_until(
        lambda: pipes.describe_pipe(Name=control),
        lambda d: d.get("CurrentState") == "RUNNING",
        timeout_s=240.0,
        interval_s=5.0,
        description=f"control pipe {control} RUNNING",
    )
    assert control_state["Description"] == collide_description, (
        f"control: the refused request's own field values are valid under a fresh name, so the "
        f"rejection is about the name; got {control_state!r}"
    )
    assert control_state["SourceParameters"]["SqsQueueParameters"]["BatchSize"] == 7, (
        f"control: describe_pipe must echo the control pipe's BatchSize 7, got "
        f"{control_state['SourceParameters']!r}"
    )

_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-delete-then-role-delete) teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_pipe_role(ctx, source_arn: str, target_arn, extra=None) -> dict[str, str]:
    """The standard pipe execution role: read the source queue, send to the target queue(s)."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arn,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
    ]
    statements.extend(extra or [])
    return _create_role(
        ctx, "pipes.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, desired_state="RUNNING",
                 wait_for="RUNNING", **extra) -> str:
    """Create a pipe and wait for CurrentState==wait_for. Returns the pipe name.

    Pipes assumes the role at create time, so only the two assume-role refusals are retried.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    # No API reports when a new role becomes assumable, so the refusal is retried to a deadline.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                DesiredState=desired_state,
                Tags=_xsvc_resource_tags(),
                **extra,
            )
            break
        except ClientError as exc:
            msg = str(exc)
            if ("cannot be assumed" in msg or "iam:PassRole" in msg) and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=name))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == wait_for,
        timeout_s=240.0,
        interval_s=5.0,
        description=f"pipe {name} {wait_for}",
    )
    return name


def _rejected_error(ctx, **kwargs) -> tuple[str, str]:
    """Call create_pipe expecting a rejection; return the AWS error code and message.

    An accepted call raises, after registering a teardown for the wrongly-created pipe.
    """
    pipes = ctx.client("pipes")
    name = kwargs.pop("Name")
    try:
        resp = pipes.create_pipe(Name=name, Tags=_xsvc_resource_tags(), **kwargs)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=name))
    raise AssertionError(
        f"create_pipe({name!r}) was ACCEPTED where real AWS rejects it; response {resp!r}"
    )


def _pipe_names(ctx, name_prefix: str) -> set[str]:
    """Every pipe name under a prefix, fully paginated (page one is not a bounded answer even with
    a server-side NamePrefix filter)."""
    pipes = ctx.client("pipes")
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NamePrefix": name_prefix}
        if token:
            kwargs["NextToken"] = token
        resp = pipes.list_pipes(**kwargs)
        names.update(p["Name"] for p in resp.get("Pipes", []))
        token = resp.get("NextToken")
        if not token:
            return names


def _describe_code(ctx, name: str) -> str:
    """describe_pipe's error code for a name expected not to exist (raises if it does exist)."""
    try:
        resp = ctx.client("pipes").describe_pipe(Name=name)
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"describe_pipe({name!r}) succeeded; the pipe exists: {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
