"""events-delivery-and-failure-deleted-lambda-target-dead-letters-as-no-permissions."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-delivery-and-failure-deleted-lambda-target-dead-letters-as-no-permissions"
GROUP = "error-propagation"
SERVICES = ["events", "lambda", "sqs"]

_RETRY = {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}
_FORWARDER = (
    "import boto3, json, os\n"
    "sqs = boto3.client('sqs')\n"
    "def handler(event, context):\n"
    "    sqs.send_message(QueueUrl=os.environ['OUT_URL'], MessageBody=json.dumps(event))\n"
    "    return {'ok': True}\n"
)


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule whose Lambda target is deleted (after a proven invocation) dead-letters each matched
    event with ERROR_CODE=NO_PERMISSIONS naming lambda:InvokeFunction, not a "not found" code, while
    a healthy SQS sibling on the same rule keeps receiving the same events."""
    events = ctx.client("events")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    source = ctx.unique_name("sim2real.edf.")
    rule_name, rule_arn = _rule(ctx, {"source": [source]})
    q_invoked = _queue(ctx, [rule_arn])
    q_ok = _queue(ctx, [rule_arn])
    q_dlq = _queue(ctx, [rule_arn])

    role_arn = _lambda_role(ctx, q_invoked[1])
    fn_name, fn_arn = _function(ctx, role_arn, _FORWARDER, {"OUT_URL": q_invoked[0]})
    lam.add_permission(
        FunctionName=fn_name, StatementId="sim2real-edf-events", Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com", SourceArn=rule_arn,
    )

    resp = events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "fn", "Arn": fn_arn, "DeadLetterConfig": {"Arn": q_dlq[1]}, "RetryPolicy": _RETRY},
            {"Id": "ok", "Arn": q_ok[1], "DeadLetterConfig": {"Arn": q_dlq[1]}, "RetryPolicy": _RETRY},
        ],
    )
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed entries: {resp.get('FailedEntries')!r}"

    def _emit():
        out = events.put_events(Entries=[{
            "Source": source, "DetailType": "LambdaGone", "Detail": json.dumps({"nonce": uuid.uuid4().hex}),
        }])
        assert out["FailedEntryCount"] == 0, f"PutEvents rejected the event: {out['Entries']!r}"
        return out["Entries"][0]["EventId"]

    # Phase 1. The function role is fresh, so its first sends can fail on IAM propagation; the
    # loop keeps emitting until an invocation has actually forwarded an event.
    invoked, ok_seen = [], []

    def _emit_and_collect_both():
        _emit()
        invoked.extend(_drain(sqs, q_invoked[0], seconds=2))
        ok_seen.extend(_drain(sqs, q_ok[0], seconds=2))
        return len(invoked), len(ok_seen)

    _poll_until(_emit_and_collect_both, lambda c: c[0] >= 1 and c[1] >= 1, timeout_s=180, interval_s=4,
                description="the function invoked and the sibling receiving, before deletion")
    early = [m for m in _drain(sqs, q_dlq[0], seconds=2)
             if m["MessageAttributes"]["TARGET_ARN"]["StringValue"] != fn_arn]
    assert early == [], f"the healthy sibling must never dead-letter, got {early!r}"

    # Break exactly one thing.
    lam.delete_function(FunctionName=fn_name)
    _drain(sqs, q_invoked[0], seconds=3)  # anything still in flight from phase 1

    emitted, ok_by_id, dlq_msgs = set(), {}, []

    def _emit_and_collect_failure():
        emitted.add(_emit())
        for msg in _drain(sqs, q_ok[0], seconds=2):
            ok_by_id[json.loads(msg["Body"])["id"]] = msg["Body"]
        dlq_msgs.extend(_drain(sqs, q_dlq[0], seconds=2))
        fn_ids = {json.loads(m["Body"])["id"] for m in dlq_msgs
                  if m["MessageAttributes"]["TARGET_ARN"]["StringValue"] == fn_arn}
        return sorted(fn_ids & set(ok_by_id) & emitted)

    joined = _poll_until(_emit_and_collect_failure, lambda ids: len(ids) >= 1, timeout_s=180, interval_s=3,
                         description="a post-deletion event dead-lettered for the function and delivered to the sibling")
    event_id = joined[0]
    late_invoked = [json.loads(m["Body"]).get("id") for m in _drain(sqs, q_invoked[0], seconds=8)]
    assert not (set(late_invoked) & emitted), (
        f"a deleted function cannot have been invoked for post-deletion events, but {late_invoked!r} arrived"
    )

    for msg in dlq_msgs:
        target = msg["MessageAttributes"]["TARGET_ARN"]["StringValue"]
        assert target == fn_arn, f"only the deleted function may dead-letter; got TARGET_ARN {target!r}"
    msg = next(m for m in dlq_msgs if json.loads(m["Body"])["id"] == event_id)
    attrs = {k: v.get("StringValue") for k, v in msg["MessageAttributes"].items()}
    assert attrs.get("ERROR_CODE") == "NO_PERMISSIONS", (
        f"a deleted Lambda target is reported as NO_PERMISSIONS by real EventBridge, got {attrs!r}"
    )
    assert "lambda:InvokeFunction" in (attrs.get("ERROR_MESSAGE") or ""), (
        f"ERROR_MESSAGE must name the denied lambda:InvokeFunction, got {attrs.get('ERROR_MESSAGE')!r}"
    )
    assert attrs.get("RULE_ARN") == rule_arn, f"expected RULE_ARN={rule_arn!r}, got {attrs!r}"
    assert json.loads(msg["Body"]) == json.loads(ok_by_id[event_id]), (
        f"the dead-lettered body must equal the sibling's copy: {msg['Body']!r} vs {ok_by_id[event_id]!r}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns a stale value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _rule(ctx, pattern):
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-edf-")
    arn = events.put_rule(Name=name, EventPattern=json.dumps(pattern))["RuleArn"]

    def _delete():
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name).get("Targets", [])]
        if ids:
            events.remove_targets(Rule=name, Ids=ids)
        events.delete_rule(Name=name)

    ctx.on_cleanup(_delete)
    return name, arn


def _queue(ctx, rule_arns):
    """A queue whose policy lets EventBridge deliver to it, scoped to exactly these rules."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-edf-q-"), tags={"sim2real": "events-delivery-and-failure"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": list(rule_arns)}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _drain(sqs, url, *, seconds):
    """Receive-and-delete for `seconds`. An empty list is a real observation, not a default."""
    out = []
    deadline = time.monotonic() + seconds
    while True:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1,
            MessageAttributeNames=["All"], AttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if time.monotonic() >= deadline:
            return out


def _lambda_role(ctx, send_to_queue_arn):
    """Execution role: sqs:SendMessage to one queue, and nothing else (no CloudWatch Logs)."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-edf-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": "events-delivery-and-failure"}])["Role"]["Arn"]

    def _delete():
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="send")
        except iam.exceptions.NoSuchEntityException:
            pass
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_delete)
    iam.put_role_policy(RoleName=name, PolicyName="send", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": send_to_queue_arn}]}))
    return arn


def _function(ctx, role_arn, code, env):
    """Create a python function, retrying while the fresh role is not yet assumable."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-edf-fn-")

    def _reap_log_group():
        # Registered BEFORE create, so it runs AFTER the function's own cleanup. A log group can
        # appear late, so look for it more than once.
        for _ in range(5):
            try:
                logs.delete_log_group(logGroupName=f"/aws/lambda/{name}")
                return
            except logs.exceptions.ResourceNotFoundException:
                time.sleep(2)

    ctx.on_cleanup(_reap_log_group)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", code)
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="handler.handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=15, Environment={"Variables": env},
                Tags={"sim2real": "events-delivery-and-failure"},
            )["FunctionArn"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise

    def _delete():
        try:
            lam.delete_function(FunctionName=name)
        except lam.exceptions.ResourceNotFoundException:
            pass  # the check deletes it itself

    ctx.on_cleanup(_delete)
    _poll_until(lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
                lambda s: s == "Active", timeout_s=90, interval_s=2, description=f"function {name} Active")
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
