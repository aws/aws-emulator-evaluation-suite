"""sam-sqs-event-role-without-queue-access-fails-the-mapping-create."""

from __future__ import annotations

import re
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-sqs-event-role-without-queue-access-fails-the-mapping-create"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "sqs", "ssm"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = "sam_sqs_event_explicit_role"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0
_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_REASON = re.compile(
    re.escape('Resource handler returned message: "Invalid request provided: The function '
              'execution role does not have permissions to call ReceiveMessage on SQS '
              "(Service: Lambda, Status Code: 400, Request ID: ")
    + _ID + re.escape(") (SDK Attempt Count: ") + r"[0-9]+" + re.escape(')" (RequestToken: ')
    + _ID + re.escape(", HandlerErrorCode: InvalidRequest)"))


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:eventing", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """With an explicit Role, SAM adds no poller policy: a role without queue access fails the
    mapping and rolls back, the message stays queued, and the granted twin consumes its message.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-sqs.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    body = (DEPLOYMENTS / _TEMPLATE / "template.yaml").read_text()

    legs = {}
    for grant in ("true", "false"):
        url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sam-sqsneg-"),
                               tags={"sim2real": CHECK})["QueueUrl"]
        ctx.on_cleanup(_teardown(lambda url=url: sqs.delete_queue(QueueUrl=url),
                                 "AWS.SimpleQueueService.NonExistentQueue"))
        arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
            "Attributes"]["QueueArn"]
        marker = ctx.unique_name("sim2real-sam-sqsneg-marker-")
        ctx.on_cleanup(_teardown(lambda m=marker: ssm.delete_parameter(Name=m),
                                 "ParameterNotFound"))
        fn = ctx.unique_name("sim2real-sam-sqsneg-")
        if grant == "true":
            ctx.on_cleanup(lambda fn=fn: _reap_log_group(logs, f"/aws/lambda/{fn}"))
        stack_id = _start_stack(ctx, cfn, ctx.unique_name("sim2real-sam-sqsneg-"), body, {
            "FunctionName": fn, "QueueArn": arn, "MarkerName": marker,
            "GrantQueueAccess": grant})
        legs[grant] = {"url": url, "arn": arn, "marker": marker, "fn": fn, "stack": stack_id}

    granted, denied = legs["true"], legs["false"]
    status = _settle(cfn, granted["stack"])
    assert status == "CREATE_COMPLETE", (
        f"control: the granted role must deploy; ended {status}: {_failures(cfn, granted['stack'])!r}")
    status = _settle(cfn, denied["stack"])
    assert status == "ROLLBACK_COMPLETE", (
        f"a role without queue access must roll the create back; ended {status}")
    failed = [(lid, reason) for lid, reason in _failures(cfn, denied["stack"])
              if lid != denied["stack"].split("/")[1]]
    assert [lid for lid, _ in failed] == ["FnWork"], f"only FnWork may fail; got {failed!r}"
    assert _REASON.fullmatch(failed[0][1] or ""), (
        f"FnWork must fail on the missing ReceiveMessage permission; got {failed[0][1]!r}")

    assert _error(lambda: lam.get_function(FunctionName=denied["fn"])) == (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{denied['fn']}",
    ), "the rolled-back function must be gone"
    assert lam.list_event_source_mappings(EventSourceArn=denied["arn"])[
        "EventSourceMappings"] == [], "no mapping may survive on the denied queue"

    mapping = lam.list_event_source_mappings(EventSourceArn=granted["arn"])[
        "EventSourceMappings"]
    assert len(mapping) == 1, f"control: one mapping on the granted queue; got {mapping!r}"
    _poll(lambda: lam.get_event_source_mapping(UUID=mapping[0]["UUID"])["State"],
          lambda s: s == "Enabled", timeout_s=120.0, interval_s=3.0,
          what="the control mapping Enabled")

    nonce = ctx.unique_name("msg-")
    for leg in (granted, denied):
        sqs.send_message(QueueUrl=leg["url"], MessageBody=nonce)
    got = _poll(lambda: _marker(ssm, granted["marker"]), lambda v: v is not None,
                timeout_s=120.0, interval_s=3.0, what="the control function writing its marker")
    assert got == nonce, f"control: the function wrote {got!r}, not {nonce!r}"
    _poll(lambda: _queue_counts(sqs, granted["url"]), lambda c: c == ("0", "0"),
          timeout_s=90.0, interval_s=3.0, what="the control queue draining")
    _poll(lambda: _queue_counts(sqs, denied["url"]), lambda c: c == ("1", "0"),
          timeout_s=60.0, interval_s=3.0, what="the denied queue's message staying queued")
    assert _marker(ssm, denied["marker"]) is None, "nothing may consume the denied queue"


def _error(fn) -> tuple[str, str]:
    """(code, message) ``fn()`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _start_stack(ctx, cfn, name: str, body: str, params: dict) -> str:
    """Start a create with its delete registered at once; the caller settles it."""
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Capabilities=_CAPS,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
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
