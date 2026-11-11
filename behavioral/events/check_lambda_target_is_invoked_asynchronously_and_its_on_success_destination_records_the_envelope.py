"""lambda-target-is-invoked-asynchronously-and-its-on-success-destination-records-the-envelope."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-target-is-invoked-asynchronously-and-its-on-success-destination-records-the-envelope"
GROUP = "lambda-target"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 240.0

# The function returns what it saw, so the destination record's responsePayload proves the
# handler ran on the delivered event rather than on something Lambda synthesised.
_HANDLER = r'''
def handler(event, context):
    return {"seen_id": event.get("id"), "seen_detail": event.get("detail"), "fn": context.function_name}
'''


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Lambda target is invoked asynchronously: its OnSuccess destination (async-only) records the
    exact envelope as requestPayload, condition Success after one invoke, and the handler's return
    value.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
    """
    events = ctx.client("events")
    lam = ctx.client("lambda")
    dest_url, dest_arn = _create_queue(ctx, "sim2real-behav-dest-")
    role_arn = _function_role(ctx, dest_arn)
    fn, fn_arn = _create_function(ctx, role_arn)
    lam.put_function_event_invoke_config(
        FunctionName=fn, MaximumRetryAttempts=0,
        DestinationConfig={"OnSuccess": {"Destination": dest_arn}})
    cfg = lam.get_function_event_invoke_config(FunctionName=fn)
    assert cfg["DestinationConfig"]["OnSuccess"]["Destination"] == dest_arn, (
        f"the OnSuccess destination reads back as {cfg['DestinationConfig']!r}"
    )

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.lambda.")
    rule, rule_arn = _create_rule(ctx, events, bus, {"source": [source]})
    lam.add_permission(FunctionName=fn, StatementId="events", Action="lambda:InvokeFunction",
                       Principal="events.amazonaws.com", SourceArn=rule_arn)
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "fn", "Arn": fn_arn}])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    resource = f"arn:aws:s3:::{ctx.unique_name('sim2real-res-')}"
    detail = {"order": ctx.unique_name("o-"), "qty": 3, "lines": [{"sku": "a"}, {"sku": "b"}]}
    # A just-created rule/permission can drop events until routing is live: re-publish fresh
    # events until one produces a destination record, then grade that event's record.
    records: list[dict] = []
    sent: dict[str, dict] = {}
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    while time.monotonic() < deadline and not any(
            r["requestPayload"].get("id") in sent for r in records):
        resp = events.put_events(Entries=[{
            "EventBusName": bus, "Source": source, "DetailType": "order.placed",
            "Detail": json.dumps(detail), "Resources": [resource]}])
        assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
        sent[resp["Entries"][0]["EventId"]] = {}
        records += _receive_for(ctx, dest_url, 20.0)
    mine = [r for r in records if r["requestPayload"].get("id") in sent]
    assert mine, (
        f"no OnSuccess destination record arrived within {_DELIVERY_TIMEOUT_S}s for any of the "
        f"{len(sent)} event(s) sent; {len(records)} other record(s)"
    )
    rec = mine[0]
    payload = rec["requestPayload"]
    event_id = payload["id"]

    assert rec["requestContext"]["condition"] == "Success", (
        f"destination record condition is {rec['requestContext']['condition']!r}"
    )
    assert rec["requestContext"]["approximateInvokeCount"] == 1, (
        f"a successful first invoke reports approximateInvokeCount "
        f"{rec['requestContext']['approximateInvokeCount']!r}"
    )
    assert rec["requestContext"]["functionArn"] == f"{fn_arn}:$LATEST", (
        "the destination record names a different function or qualifier than the target's "
        f"unqualified ARN resolves to (qualifier {rec['requestContext']['functionArn'].rsplit(':', 1)[-1]!r})"
    )
    want_keys = ["account", "detail", "detail-type", "id", "region", "resources", "source",
                 "time", "version"]
    assert sorted(payload) == want_keys, f"the invocation payload carries keys {sorted(payload)!r}"
    assert (payload["version"], payload["source"], payload["detail-type"], payload["account"],
            payload["region"], payload["resources"], payload["detail"]) == (
            "0", source, "order.placed", ctx.account, ctx.region, [resource], detail), (
        f"the invocation payload is not the published envelope: source match "
        f"{payload['source'] == source!r}, detail-type {payload['detail-type']!r}, resources "
        f"match {payload['resources'] == [resource]!r}, detail {payload['detail']!r}"
    )
    assert rec["responsePayload"] == {"seen_id": event_id, "seen_detail": detail, "fn": fn}, (
        f"the handler's return value does not reflect the delivered event: "
        f"{rec['responsePayload']!r}"
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
