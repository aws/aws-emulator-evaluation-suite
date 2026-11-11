"""sam-sqs-event-creates-esm-that-consumes."""

from __future__ import annotations

import json
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-sqs-event-creates-esm-that-consumes"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "sqs", "ssm"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = "sam_sqs_event"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """An SQS event expands to an EventSourceMapping plus the SQS poller policy on the generated role,
    and a sent message is consumed: the function writes its body to SSM and the queue drains.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-sqs.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    fn = ctx.unique_name("sim2real-sam-sqs-")
    stack = ctx.unique_name("sim2real-sam-sqs-")
    marker = ctx.unique_name("sim2real-sam-sqs-marker-")
    nonce = ctx.unique_name("msg-")
    body = (DEPLOYMENTS / _TEMPLATE / "template.yaml").read_text()

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sam-sqs-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    partition = queue_arn.split(":")[1]
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=marker), "ParameterNotFound"))
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    stack_id = _create_stack(ctx, cfn, stack, body,
                             {"FunctionName": fn, "QueueArn": queue_arn, "MarkerName": marker})

    resources = _processed(cfn, stack_id)["Resources"]
    mapping = resources.get("FnWork", {})
    types = {k: r["Type"] for k, r in resources.items()}
    assert mapping.get("Type") == "AWS::Lambda::EventSourceMapping", (
        f"the SQS event must become FnWork, an EventSourceMapping; resources {types!r}")
    assert mapping["Properties"] == {"BatchSize": 1, "EventSourceArn": {"Ref": "QueueArn"},
                                     "FunctionName": {"Ref": "Fn"}}, (
        f"FnWork properties {mapping['Properties']!r}")
    poller = f"arn:{partition}:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
    managed = resources["FnRole"]["Properties"]["ManagedPolicyArns"]
    basic = f"arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    assert managed == [basic, poller], (
        f"the generated role must carry the basic execution and SQS poller policies; got {managed!r}")

    mappings = lam.list_event_source_mappings(EventSourceArn=queue_arn)["EventSourceMappings"]
    assert [m["FunctionArn"].rsplit(":", 1)[-1] for m in mappings] == [fn], (
        f"exactly one mapping must connect the queue to {fn}; got {mappings!r}")
    uuid = mappings[0]["UUID"]
    _poll(lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == "Enabled",
          timeout_s=120.0, interval_s=3.0, what="the event source mapping Enabled")

    sqs.send_message(QueueUrl=url, MessageBody=nonce)
    got = _poll(lambda: _marker(ssm, marker), lambda v: v is not None, timeout_s=120.0,
                interval_s=3.0, what="the function writing the message body to SSM")
    assert got == nonce, f"the function wrote {got!r}, not the message body {nonce!r}"
    _poll(lambda: _queue_counts(sqs, url), lambda c: c == ("0", "0"), timeout_s=90.0,
          interval_s=3.0, what="the consumed message leaving the queue")


def _marker(ssm, name: str):
    """The marker parameter's value, or None while the function has not written it."""
    try:
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ParameterNotFound":
            return None
        raise


def _queue_counts(sqs, url: str) -> tuple[str, str]:
    """(visible, in flight) message counts of the queue."""
    attrs = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return attrs["ApproximateNumberOfMessages"], attrs["ApproximateNumberOfMessagesNotVisible"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, done, *, timeout_s: float, interval_s: float = 3.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _processed(cfn, stack_id: str) -> dict:
    body = cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]
    return body if isinstance(body, dict) else json.loads(body)


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by StackId and wait for DELETE_COMPLETE; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _create_stack(ctx, cfn, name: str, body: str, params: dict) -> str:
    """Create the stack with its delete registered at once; assert CREATE_COMPLETE."""
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Capabilities=_CAPS,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {name} ended {status}: {_failures(cfn, stack_id)!r}"
    return stack_id


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 1.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads, ``interval_s`` apart, find it
    absent; a late log flush that re-creates the group is deleted again."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(f"log group {name} still re-appears after {budget_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
