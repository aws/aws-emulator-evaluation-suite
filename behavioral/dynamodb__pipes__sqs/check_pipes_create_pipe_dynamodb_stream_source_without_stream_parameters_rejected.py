"""pipes-create-pipe-dynamodb-stream-source-without-stream-parameters-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-create-pipe-dynamodb-stream-source-without-stream-parameters-rejected"

GROUP = "rejection"

SERVICES = ["dynamodb", "pipes", "sqs"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreatePipe with a DynamoDB stream source and no SourceParameters is refused with
    ValidationException and creates nothing, while the same call with StartingPosition reaches
    RUNNING. SourceParameters is optional in the model; the requirement depends on the source type.
    """
    ddb = ctx.client("dynamodb")

    table = _xname(ctx, "tbl")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    stream_arn = _poll_until(
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t.get("TableStatus") == "ACTIVE" and t.get("LatestStreamArn"),
        timeout_s=120.0,
        interval_s=3.0,
        description=f"table {table} ACTIVE with a stream",
    )["LatestStreamArn"]

    target = _create_queue(ctx)
    role = _create_role(
        ctx,
        "pipes.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "dynamodb:DescribeStream",
                        "dynamodb:GetRecords",
                        "dynamodb:GetShardIterator",
                        "dynamodb:ListStreams",
                    ],
                    "Resource": stream_arn,
                },
                {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target["arn"]},
            ],
        },
    )

    # Control runs first and must reach RUNNING, so the missing SourceParameters is the only
    # difference when the second call is refused.
    control = _create_pipe(
        ctx,
        source=stream_arn,
        target=target["arn"],
        role_arn=role["arn"],
        SourceParameters={
            "DynamoDBStreamParameters": {"StartingPosition": "LATEST", "BatchSize": 1}
        },
    )
    described = ctx.client("pipes").describe_pipe(Name=control)
    assert described["Source"] == stream_arn, (
        f"control leg: describe_pipe must report the DynamoDB stream {stream_arn!r} as the source, "
        f"got {described['Source']!r}"
    )
    assert (
        described["SourceParameters"]["DynamoDBStreamParameters"]["StartingPosition"] == "LATEST"
    ), (
        f"control leg: describe_pipe must echo the accepted StartingPosition, got "
        f"{described['SourceParameters']!r}"
    )

    rejected_name = _xname(ctx, "pipe")
    code, message = _rejected_code(
        ctx,
        Name=rejected_name,
        RoleArn=role["arn"],
        Source=stream_arn,
        Target=target["arn"],
        DesiredState="RUNNING",
    )
    assert code == "ValidationException", (
        f"a DynamoDB stream source with no SourceParameters.DynamoDBStreamParameters must be "
        f"refused with ValidationException, got {code!r}"
    )
    assert message == (
        '{"ValidationErrorFields":[{"Name":"SourceParameters.DynamoDBStreamParameters",'
        '"Message":"Missing required parameter."}]}'
    ), (
        f"the refused CreatePipe answered message {message!r}"
    )

    assert rejected_name not in _pipe_names(ctx, rejected_name), (
        f"the refused pipe {rejected_name!r} appears in the fully-paginated list_pipes result: "
        f"{sorted(_pipe_names(ctx, rejected_name))!r}"
    )
    describe_code, describe_message = _describe_code(ctx, rejected_name)
    assert describe_code == "NotFoundException", (
        f"describe_pipe on the refused name {rejected_name!r} must raise NotFoundException, got "
        f"{describe_code!r}"
    )
    assert describe_message == f"Pipe {rejected_name} does not exist.", (
        f"describe_pipe on the refused name {rejected_name!r} answered message "
        f"{describe_message!r}"
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
    """Create a pipe and wait for CurrentState==wait_for; return the pipe name.

    Retries only the assume-role errors of a freshly created role (IAM propagation), never a
    ValidationException, so a permanent rejection is not turned into a timeout.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    last_err = None
    for _ in range(8):
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
            if "cannot be assumed" in msg or "iam:PassRole" in msg:
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create pipe {name}: {last_err}")
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=name))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == wait_for,
        timeout_s=240.0,
        interval_s=5.0,
        description=f"pipe {name} {wait_for}",
    )
    return name


def _rejected_code(ctx, **kwargs) -> tuple[str, str]:
    """Call create_pipe expecting a rejection; return the AWS error (code, message).

    An accepted call raises (after registering teardown) instead of reading as a code mismatch.
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
    """Every pipe name under a prefix, fully paginated (page one is not a bounded answer even
    with a server-side NamePrefix filter)."""
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


def _describe_code(ctx, name: str) -> tuple[str, str]:
    """describe_pipe's error (code, message) for a name expected not to exist (raises if it
    does exist)."""
    try:
        resp = ctx.client("pipes").describe_pipe(Name=name)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"describe_pipe({name!r}) succeeded; the pipe exists: {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
