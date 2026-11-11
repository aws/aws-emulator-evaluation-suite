"""pipes-enrichment-standard-state-machine-rejected-express-accepted."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-enrichment-standard-state-machine-rejected-express-accepted"

GROUP = "error-propagation"

SERVICES = ["pipes", "sqs", "stepfunctions"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """CreatePipe accepts a STANDARD state machine as Enrichment, but every record fails
    enrichment and never reaches the target, while the identical wiring with an EXPRESS twin
    delivers. The pipe's execution log names the Step Functions error Pipes got back.
    """
    # Each pipe reads its own source queue, so neither can consume the other's records.
    standard_source = _create_queue(ctx, VisibilityTimeout="30")
    express_source = _create_queue(ctx)
    target = _create_queue(ctx)

    standard_sm = _create_state_machine(ctx, sm_type="STANDARD")
    express_sm = _create_state_machine(ctx, sm_type="EXPRESS")

    log_group = f"/aws/vendedlogs/pipes/{_xname(ctx, 'lg')}"
    logs = ctx.client("logs")
    logs.create_log_group(logGroupName=log_group, tags=_xsvc_resource_tags())
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=log_group),
                             "ResourceNotFoundException"))
    described = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"]
    assert described, f"log group {log_group!r} was created but does not describe"
    log_group_arn = described[0]["arn"].rstrip("*").rstrip(":")

    role = _create_pipe_role(
        ctx,
        [standard_source["arn"], express_source["arn"]],
        target["arn"],
        extra=[
            {
                "Effect": "Allow",
                "Action": ["states:StartSyncExecution", "states:StartExecution"],
                "Resource": [standard_sm["arn"], express_sm["arn"]],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": [log_group_arn, log_group_arn + ":*"],
            },
        ],
    )

    # Positive control first: the EXPRESS twin delivers, and its latency sizes the absence window.
    express_pipe = _create_pipe(
        ctx,
        source=express_source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        Enrichment=express_sm["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
    )
    described = ctx.client("pipes").describe_pipe(Name=express_pipe)
    assert described["Enrichment"] == express_sm["arn"], (
        f"control leg: describe_pipe must echo the accepted EXPRESS enrichment "
        f"{express_sm['arn']!r}, got {described.get('Enrichment')!r}"
    )
    assert described["CurrentState"] == "RUNNING", (
        f"control leg: pipe with an EXPRESS enrichment must reach RUNNING, got "
        f"{described['CurrentState']!r}"
    )
    sqs = ctx.client("sqs")
    control_marker = _xname(ctx, "express-mark")
    sqs.send_message(QueueUrl=express_source["url"],
                     MessageBody=json.dumps({"marker": control_marker}))
    started = time.monotonic()
    delivered = _poll_until(
        ctx,
        lambda: _receive_all(ctx, target["url"]),
        lambda msgs: any(control_marker in m["Body"] for m in msgs),
        timeout_s=150.0,
        interval_s=1.0,
        description=f"the EXPRESS-enriched control record carrying {control_marker!r}",
    )
    latency_s = time.monotonic() - started
    assert any(control_marker in m["Body"] for m in delivered), (
        f"control leg: the EXPRESS enrichment's record carrying {control_marker!r} never reached "
        f"the target; saw {delivered!r}"
    )

    standard_pipe = _create_pipe(
        ctx,
        source=standard_source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        Enrichment=standard_sm["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        LogConfiguration={
            "CloudwatchLogsLogDestination": {"LogGroupArn": log_group_arn},
            "Level": "ERROR",
            "IncludeExecutionData": ["ALL"],
        },
    )
    desc = ctx.client("pipes").describe_pipe(Name=standard_pipe)
    assert desc["Enrichment"] == standard_sm["arn"], (
        f"CreatePipe must accept a STANDARD state machine as Enrichment and echo it back, got "
        f"{desc.get('Enrichment')!r}"
    )
    assert desc["CurrentState"] == "RUNNING", (
        f"a pipe naming a STANDARD state machine as Enrichment must still reach RUNNING, got "
        f"{desc['CurrentState']!r}"
    )

    marker = _xname(ctx, "standard-mark")
    sqs.send_message(QueueUrl=standard_source["url"], MessageBody=json.dumps({"marker": marker}))

    error_events = _poll_until(
        ctx,
        lambda: logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"').get(
            "events", []
        ),
        lambda evs: bool(evs),
        timeout_s=150.0,
        interval_s=5.0,
        description=f"an ERROR-level execution log record carrying {marker!r} in {log_group!r}",
    )
    error_record = json.loads(error_events[0]["message"])
    assert error_record.get("messageType") == "EnrichmentInvocationFailed", (
        f"the logged failure for a STANDARD enrichment must be EnrichmentInvocationFailed, got "
        f"{error_record.get('messageType')!r}: {error_record!r}"
    )
    error = error_record.get("error", {})
    assert error.get("awsService") == "states", (
        f"the enrichment failure must be attributed to the states service, got "
        f"{error.get('awsService')!r}: {error_record!r}"
    )
    assert error.get("httpStatusCode") == 400, (
        f"the Step Functions refusal must surface as HTTP 400, got {error.get('httpStatusCode')!r}"
    )
    assert error.get("exceptionType") == "BadRequest", (
        f"the Step Functions refusal must surface as exceptionType BadRequest, got "
        f"{error.get('exceptionType')!r}"
    )
    assert error.get("resourceArn") == standard_sm["arn"], (
        f"the enrichment failure must name the STANDARD state machine {standard_sm['arn']!r}, "
        f"got {error.get('resourceArn')!r}"
    )
    request_id = error.get("requestId")
    assert request_id, f"the enrichment failure must carry the Step Functions request id: {error!r}"
    expected_message = (
        "Enrichment invocation failed with error from States: This operation is not supported "
        f"by this type of state machine (Service: Sfn, Status Code: 400, Request ID: "
        f"{request_id}) (SDK Attempt Count: 1)"
    )
    assert error.get("message") == expected_message, (
        f"unexpected enrichment failure message for a STANDARD state machine: "
        f"{error.get('message')!r} != {expected_message!r}"
    )

    seen = _absent_for(
        lambda: [m for m in _receive_all(ctx, target["url"]) if marker in m["Body"]], latency_s
    )
    assert seen == [], (
        f"a record whose STANDARD enrichment failed must never reach the target; "
        f"the target queue held {seen!r}"
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=1.0,
                description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _receive_all(ctx, url: str) -> list[dict]:
    """One drain pass over `url`, deleting what it reads. Returns the raw SQS messages."""
    sqs = ctx.client("sqs")
    out: list[dict] = []
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        out.append(msg)
    return out


def _absent_for(observe, latency_s: float, *, factor: float = 3.0, floor_s: float = 10.0,
                poll_s: float = 2.0) -> list:
    """Everything `observe()` returns over `max(floor_s, factor * latency_s)` seconds."""
    window = max(floor_s, factor * latency_s)
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


def _create_queue(ctx, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    resp = sqs.create_queue(QueueName=name, Attributes=dict(attrs), tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                              "AWS.SimpleQueueService.NonExistentQueue"))
    return {"name": name, "url": url, "arn": arn}


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it's gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-delete-then-role-delete) teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
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


def _create_pipe_role(ctx, source_arns: list[str], target_arn: str, extra=None) -> dict[str, str]:
    """The pipe execution role: read the source queues, send to the target queue, plus
    whatever `extra` statements the scenario needs."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arns,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
    ]
    statements.extend(extra or [])
    return _create_role(
        ctx, "pipes.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )


def _create_state_machine(ctx, sm_type: str) -> dict[str, str]:
    """A one-state Pass-state state machine of the given type (STANDARD or EXPRESS). The role
    needs no permissions: a Pass state calls nothing."""
    role = _create_role(ctx, "states.amazonaws.com")
    name = _xname(ctx, f"sm-{sm_type.lower()}")
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    last_err = None
    arn = None
    for _ in range(8):
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role["arn"],
                type=sm_type,
                tags=[{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or "is not authorized to assume" in msg:
                last_err = exc
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create {sm_type} state machine {name}: {last_err}")
    ctx.on_cleanup(lambda: _delete_state_machine_and_wait(ctx, arn))
    return {"name": name, "arn": arn}


def _delete_state_machine_and_wait(ctx, arn: str, timeout_s: float = 180.0) -> None:
    """DeleteStateMachine is asynchronous; wait until DescribeStateMachine reports it gone."""
    sfn = ctx.client("stepfunctions")
    try:
        sfn.delete_state_machine(stateMachineArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        time.sleep(2)
    raise TimeoutError(f"state machine {arn} still exists {timeout_s:.0f}s after DeleteStateMachine")


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, **extra) -> str:
    """Create a pipe and wait for CurrentState==RUNNING; return the pipe name."""
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
                DesiredState="RUNNING",
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
    ctx.on_cleanup(_teardown(lambda: _delete_pipe_when_stable(ctx, name), "NotFoundException"))
    _poll_until(
        ctx,
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == "RUNNING",
        timeout_s=240.0,
        interval_s=5.0,
        description=f"pipe {name} RUNNING",
    )
    return name


def _delete_pipe_when_stable(ctx, name: str) -> None:
    """DeletePipe refuses while the pipe is CREATING/UPDATING; wait for a stable state first."""
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 180.0
    state = pipes.describe_pipe(Name=name).get("CurrentState")
    while state in ("CREATING", "UPDATING"):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"pipe {name} still {state} 180s into its teardown")
        time.sleep(5)
        state = pipes.describe_pipe(Name=name).get("CurrentState")
    pipes.delete_pipe(Name=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
