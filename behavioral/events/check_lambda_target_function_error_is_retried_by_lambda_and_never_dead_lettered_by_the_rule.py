"""lambda-target-function-error-is-retried-by-lambda-and-never-dead-lettered-by-the-rule."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-target-function-error-is-retried-by-lambda-and-never-dead-lettered-by-the-rule"
GROUP = "lambda-target"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 300.0
_LAMBDA_RETRIES = 1

_HANDLER = r'''
def handler(event, context):
    raise RuntimeError("sim2real deliberate failure for " + str(event.get("id")))
'''


# timing:real-time — cooldown: 60 s https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Lambda target whose handler raises is retried by Lambda (OnFailure record, RetriesExhausted
    after 1 + MaximumRetryAttempts invokes, carrying the envelope and error), never by the rule's
    DLQ.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
    """
    events = ctx.client("events")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    dest_url, dest_arn = _create_queue(ctx, "sim2real-behav-dest-")
    dlq_url, dlq_arn = _create_queue(ctx, "sim2real-behav-dlq-")
    # The DLQ admits EventBridge, so an empty DLQ means no dead letter, not a missing grant.
    sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": dlq_arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}}}]})})
    role_arn = _function_role(ctx, dest_arn)
    fn, fn_arn = _create_function(ctx, role_arn)
    lam.put_function_event_invoke_config(
        FunctionName=fn, MaximumRetryAttempts=_LAMBDA_RETRIES,
        DestinationConfig={"OnFailure": {"Destination": dest_arn}})

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.lambda.")
    rule, rule_arn = _create_rule(ctx, events, bus, {"source": [source]})
    lam.add_permission(FunctionName=fn, StatementId="events", Action="lambda:InvokeFunction",
                       Principal="events.amazonaws.com", SourceArn=rule_arn)
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[{
        "Id": "fn", "Arn": fn_arn, "DeadLetterConfig": {"Arn": dlq_arn},
        "RetryPolicy": {"MaximumRetryAttempts": 2, "MaximumEventAgeInSeconds": 60}}])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    detail = {"order": ctx.unique_name("o-")}
    records: list[dict] = []
    sent: set[str] = set()
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < deadline and not any(
            r["requestPayload"].get("id") in sent for r in records):
        # Re-publish (at most every 60 s) until one event's failure record arrives: a
        # just-created rule can drop events until routing is live, and Lambda's retry adds
        # its own back-off before the record is written.
        if time.monotonic() >= next_put:
            resp = events.put_events(Entries=[{
                "EventBusName": bus, "Source": source, "DetailType": "order.placed",
                "Detail": json.dumps(detail)}])
            assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
            sent.add(resp["Entries"][0]["EventId"])
            next_put = time.monotonic() + 60.0
        records += _receive_for(ctx, dest_url, 10.0)
    mine = [r for r in records if r["requestPayload"].get("id") in sent]
    assert mine, (
        f"no OnFailure destination record arrived within {_DELIVERY_TIMEOUT_S}s for any of the "
        f"{len(sent)} event(s) sent; {len(records)} other record(s)"
    )
    rec = mine[0]
    event_id = rec["requestPayload"]["id"]
    ctxr = rec["requestContext"]
    assert ctxr["condition"] == "RetriesExhausted", f"OnFailure condition is {ctxr['condition']!r}"
    assert ctxr["approximateInvokeCount"] == 1 + _LAMBDA_RETRIES, (
        f"MaximumRetryAttempts={_LAMBDA_RETRIES} must give {1 + _LAMBDA_RETRIES} invokes; the "
        f"record reports {ctxr['approximateInvokeCount']!r}"
    )
    assert (rec["requestPayload"]["source"], rec["requestPayload"]["detail"]) == (source, detail), (
        f"the failed invoke's payload is not the published event: {rec['requestPayload']!r}"
    )
    assert rec["responseContext"].get("functionError") == "Unhandled", (
        f"responseContext is {rec['responseContext']!r}"
    )
    assert (rec["responsePayload"]["errorType"], rec["responsePayload"]["errorMessage"]) == (
        "RuntimeError", f"sim2real deliberate failure for {event_id}"), (
        f"the record does not carry the handler's error: {rec['responsePayload']!r}"
    )

    dead = _receive_for(ctx, dlq_url, 20.0)
    assert dead == [], (
        f"a handler error must not dead-letter on the rule target; its DLQ received "
        f"{len(dead)} message(s) with ids match "
        f"{[d.get('id') in sent for d in dead]!r}"
    )


# The function's role grants only sqs:SendMessage on the destination queue -- no CloudWatch Logs
# permissions -- so no /aws/lambda log group is ever created for it.

def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("index.py")
        info.external_attr = 0o644 << 16
        zf.writestr(info, _HANDLER)
    return buf.getvalue()


def _create_queue(ctx, prefix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _function_role(ctx, dest_arn: str) -> str:
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-fn-")
    arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    iam.put_role_policy(RoleName=role, PolicyName="destination", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dest_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName="destination"))
    return arn


def _create_function(ctx, role_arn: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(
                FunctionName=fn, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": _zip()}, Timeout=10, Tags={"sim2real": CHECK},
            )["FunctionArn"]
            break
        except ClientError as exc:
            # A just-created execution role is not yet assumable by Lambda; nothing to poll.
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn, arn


def _create_bus(ctx, events) -> str:
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus


def _create_rule(ctx, events, bus: str, pattern: dict) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = events.put_rule(Name=name, EventBusName=bus, EventPattern=json.dumps(pattern))["RuleArn"]

    def _delete() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name, EventBusName=bus)["Targets"]]
        if ids:
            events.remove_targets(Rule=name, EventBusName=bus, Ids=ids)
        events.delete_rule(Name=name, EventBusName=bus)

    ctx.on_cleanup(_delete)
    return name, arn


def _receive_for(ctx, url: str, seconds: float) -> list[dict]:
    sqs = ctx.client("sqs")
    out: list[dict] = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=5).get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if out:
            return out
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
