"""kinesis-source-dead-letter-config-requires-sqs-or-sns."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-source-dead-letter-config-requires-sqs-or-sns"
GROUP = "validation"
SERVICES = ["kinesis", "pipes", "sns", "sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A Kinesis-source pipe's DeadLetterConfig.Arn round-trips for a running pipe's SQS queue or SNS
    topic and is absent when never set; a stream ARN, neither SQS nor SNS, reaches CREATE_FAILED with
    the exact StateReason instead of a synchronous refusal.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/pipes-reference/API_DeadLetterConfig.html
    """
    pipes = ctx.client("pipes")
    kinesis = ctx.client("kinesis")
    sns = ctx.client("sns")

    stream_name = _xname(ctx, "stream")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags=dict(_MANAGED))
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    stream_arn = _poll_until(
        ctx,
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"],
        lambda s: s.get("StreamStatus") == "ACTIVE",
        cap_s=180.0,
        interval_s=5.0,
        description=f"stream {stream_name} ACTIVE",
    )["StreamARN"]

    target = _create_queue(ctx)
    dlq = _create_queue(ctx)
    topic_arn = _create_topic(ctx)
    role = _create_pipe_role(ctx, stream_arn=stream_arn, target_arn=target["arn"],
                             dlq_arns=[dlq["arn"], topic_arn])

    no_dlq = _create_pipe(
        ctx, source=stream_arn, target=target["arn"], role_arn=role["arn"],
        SourceParameters={"KinesisStreamParameters": {"StartingPosition": "TRIM_HORIZON"}},
    )
    ksp = pipes.describe_pipe(Name=no_dlq)["SourceParameters"]["KinesisStreamParameters"]
    assert "DeadLetterConfig" not in ksp, (
        f"a pipe created with no DeadLetterConfig must omit the key from describe_pipe, got "
        f"{ksp!r}"
    )

    # The SQS and SNS pipes start, as the stream-ARN pipe below does, so the destination type
    # check that refuses the stream ARN once the pipe starts also runs for them and passes.
    sqs_dlq = _create_pipe(
        ctx, source=stream_arn, target=target["arn"], role_arn=role["arn"], desired_state="RUNNING",
        SourceParameters={"KinesisStreamParameters": {
            "StartingPosition": "TRIM_HORIZON",
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        }},
    )
    sqs_desc = pipes.describe_pipe(Name=sqs_dlq)["SourceParameters"]["KinesisStreamParameters"]
    assert sqs_desc.get("DeadLetterConfig") == {"Arn": dlq["arn"]}, (
        f"an SQS queue ARN as DeadLetterConfig.Arn must round-trip exactly, got "
        f"{sqs_desc.get('DeadLetterConfig')!r}, expected {{'Arn': {dlq['arn']!r}}}"
    )

    sns_dlq = _create_pipe(
        ctx, source=stream_arn, target=target["arn"], role_arn=role["arn"], desired_state="RUNNING",
        SourceParameters={"KinesisStreamParameters": {
            "StartingPosition": "TRIM_HORIZON",
            "DeadLetterConfig": {"Arn": topic_arn},
        }},
    )
    sns_desc = pipes.describe_pipe(Name=sns_dlq)["SourceParameters"]["KinesisStreamParameters"]
    assert sns_desc.get("DeadLetterConfig") == {"Arn": topic_arn}, (
        f"an SNS topic ARN as DeadLetterConfig.Arn must round-trip exactly, got "
        f"{sns_desc.get('DeadLetterConfig')!r}, expected {{'Arn': {topic_arn!r}}}"
    )

    # A Kinesis stream ARN is neither SQS nor SNS. CreatePipe accepts the request
    # synchronously (the type check happens once the pipe starts), then the pipe fails
    # asynchronously into CREATE_FAILED rather than being refused at the API call.
    bad_name = _xname(ctx, "pipe")
    ctx.on_cleanup(lambda: _delete_pipe(ctx, bad_name))
    pipes.create_pipe(
        Name=bad_name, RoleArn=role["arn"], Source=stream_arn, Target=target["arn"],
        DesiredState="RUNNING",
        SourceParameters={"KinesisStreamParameters": {
            "StartingPosition": "TRIM_HORIZON",
            "DeadLetterConfig": {"Arn": stream_arn},
        }},
        Tags=_MANAGED,
    )
    terminal = _poll_until(
        ctx,
        lambda: pipes.describe_pipe(Name=bad_name),
        lambda d: d.get("CurrentState") != "CREATING",
        cap_s=120.0,
        interval_s=5.0,
        description=f"pipe {bad_name} reaching a terminal state",
    )
    assert terminal["CurrentState"] == "CREATE_FAILED", (
        f"a Kinesis-source pipe whose DeadLetterConfig.Arn names a Kinesis stream must fail "
        f"asynchronously into CREATE_FAILED, got CurrentState={terminal['CurrentState']!r} "
        f"(StateReason={terminal.get('StateReason')!r})"
    )
    assert terminal["StateReason"] == (
        "Input parameter is invalid from the request due to : The service specified by the "
        "TargetArn isn't supported as a destination."
    ), f"the CREATE_FAILED pipe's StateReason was {terminal.get('StateReason')!r}"
    assert bad_name in _pipe_names(ctx, bad_name), (
        f"a pipe that reached CREATE_FAILED must still appear in list_pipes under its name; "
        f"{bad_name!r} did not"
    )


_PREFIX = "sim2real-kdlq-"
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _expired(ctx, description, timeout_s, detail):
    """The error for a capped wait that ran out: TimeoutError when the run budget ended it."""
    if _budget_spent(ctx):
        return TimeoutError(f"{description}: the run budget ended first; not graded")
    return AssertionError(f"{description}: not met within {timeout_s:.0f}s; {detail}")


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name so any leftover can be found by tag or prefix."""
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(ctx, probe, predicate, *, cap_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result), under a deadline capped by the run budget."""
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise _expired(ctx, description, timeout_s, f"last: {last!r}")


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")
    url = sqs.create_queue(QueueName=name, tags=dict(_MANAGED))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    name = _xname(ctx, "topic")
    arn = sns.create_topic(Name=name, Tags=[{"Key": k, "Value": v} for k, v in _MANAGED.items()])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_pipe_role(ctx, *, stream_arn: str, target_arn: str, dlq_arns: list[str]) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "kinesis:DescribeStream", "kinesis:DescribeStreamSummary", "kinesis:GetRecords",
                "kinesis:GetShardIterator", "kinesis:ListShards", "kinesis:ListStreams",
                "kinesis:SubscribeToShard",
            ],
            "Resource": stream_arn,
        },
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": target_arn},
        {"Effect": "Allow", "Action": ["sqs:SendMessage", "sns:Publish"], "Resource": dlq_arns},
    ]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="pipe-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return {"name": role_name, "arn": arn}


def _delete_role(ctx, role_name: str) -> None:
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


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, desired_state: str = "STOPPED",
                 **extra: Any) -> str:
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    timeout_s = _budget_s(ctx, 90.0)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            pipes.create_pipe(
                Name=name, RoleArn=role_arn, Source=source, Target=target,
                DesiredState=desired_state, Tags=_MANAGED, **extra,
            )
            break
        except ClientError as exc:
            text = str(exc)
            if "cannot be assumed" not in text and "iam:PassRole" not in text:
                raise
            if time.monotonic() >= deadline:
                raise _expired(ctx, f"pipe {name!r} role assumable", timeout_s, f"last error: {exc!r}") from exc
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_pipe(ctx, name))
    settled = _poll_until(
        ctx,
        lambda: pipes.describe_pipe(Name=name),
        lambda d: d.get("CurrentState") in (desired_state, "CREATE_FAILED", "START_FAILED"),
        cap_s=180.0,
        interval_s=5.0,
        description=f"pipe {name} {desired_state}",
    )
    assert settled["CurrentState"] == desired_state, (
        f"pipe {name} settled in {settled['CurrentState']!r} ({settled.get('StateReason')!r}), "
        f"expected {desired_state!r}"
    )
    return name


def _delete_pipe(ctx, name: str) -> None:
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)


def _pipe_names(ctx, name_prefix: str) -> set[str]:
    """Every pipe name under name_prefix, fully paginated."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
