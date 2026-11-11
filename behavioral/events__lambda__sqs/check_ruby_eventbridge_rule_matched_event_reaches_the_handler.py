"""ruby-eventbridge-rule-matched-event-reaches-the-handler."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ruby-eventbridge-rule-matched-event-reaches-the-handler"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "sqs"]

_HANDLER = """\
require 'json'
require 'aws-sdk-sqs'

def lambda_handler(event:, context:)
  sqs = Aws::SQS::Client.new
  sqs.send_message(
    queue_url: ENV['OBSERVE_QUEUE_URL'],
    message_body: event.to_json
  )
  { 'ok' => true }
end
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule target invokes a ruby3.4 handler with the whole matched custom event:
    its source, detail-type and detail verbatim, and the account/region of the bus that matched it.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-targets.html
    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-events.html
    """
    observe = _queue(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": observe["arn"]},
    ])
    fn = _function(ctx, role["arn"], _HANDLER, env={"OBSERVE_QUEUE_URL": observe["url"]})

    events = ctx.client("events")
    source = ctx.unique_name("sim2real.xsvc.source")
    detail_type = "sim2real-ruby-probe"
    rule_name = ctx.unique_name("sim2real-xsvc-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source], "detail-type": [detail_type]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(_teardown(lambda: events.delete_rule(Name=rule_name), "ResourceNotFoundException"))

    ctx.client("lambda").add_permission(
        FunctionName=fn["name"], StatementId="events-invoke", Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com", SourceArn=rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "ruby-target", "Arn": fn["arn"]}])
    ctx.on_cleanup(_teardown(
        lambda: events.remove_targets(Rule=rule_name, Ids=["ruby-target"]), "ResourceNotFoundException"))

    sqs = ctx.client("sqs")
    ev, detail = _send_until_delivered(ctx, events, sqs, observe["url"], source, detail_type)
    assert ev["source"] == source, f"event source was {ev['source']!r}, expected {source!r}"
    assert ev["detail-type"] == detail_type, f"detail-type was {ev['detail-type']!r}"
    assert ev["detail"] == detail, f"detail was {ev['detail']!r}, expected {detail!r}"
    assert ev.get("resources") == [], (
        f"a PutEvents entry naming no Resources must deliver an empty list, got {ev.get('resources')!r}")
    assert ev.get("account") == ctx.account, f"account was {ev.get('account')!r}"
    assert ev.get("region") == ctx.region, f"region was {ev.get('region')!r}"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, timeout_s, interval_s=2.0, what):
    budgeted = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budgeted
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"waiting until {what}: the run budget ended first; not graded")
            raise AssertionError(f"timed out after {budgeted:.0f}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _send_until_delivered(ctx, events, sqs, queue_url, source, detail_type, *,
                          timeout_s=150.0, round_s=20.0):
    """PutEvents with a fresh marker, polling for its delivery; re-emits with a new marker each
    round because a brand-new rule/target can drop an event sent before add_permission and
    put_targets finish propagating, rather than ever retrying it."""
    budgeted = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budgeted
    pending: dict = {}
    while True:
        marker = ctx.unique_name("marker")
        detail = {"marker": marker, "n": 7}
        resp = events.put_events(Entries=[{
            "Source": source, "DetailType": detail_type, "Detail": json.dumps(detail)}])
        assert resp.get("FailedEntryCount", 0) == 0, f"PutEvents failed: {resp['Entries']}"
        pending[marker] = detail
        round_deadline = min(deadline, time.monotonic() + round_s)
        while True:
            for r in _drain(sqs, queue_url):
                m = r.get("detail", {}).get("marker")
                if m in pending:
                    return r, pending[m]
            if time.monotonic() >= round_deadline:
                break
            time.sleep(2)
        if time.monotonic() >= deadline:
            break
    if _budget_spent(ctx):
        raise TimeoutError("no matched event ever arrived: the run budget ended first; not graded")
    raise AssertionError(
        f"no matched event arrived after retrying with fresh markers; tried {list(pending)}")


def _zip(code: str, filename: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _execution_role(ctx, statements) -> dict:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"), "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"]}


def _function(ctx, role_arn, code, *, env=None, timeout=15, memory=128) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": "ruby3.4", "Handler": "lambda_function.lambda_handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code, "lambda_function.rb")},
              "Timeout": timeout, "MemorySize": memory, "Tags": {"sim2real": CHECK}}
    if env:
        kwargs["Environment"] = {"Variables": env}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", ""):
                return None
            raise

    out = _poll(ctx, create, lambda r: r is not None, timeout_s=90,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"), timeout_s=90,
                 what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    assert conf["Runtime"] == "ruby3.4", f"expected Runtime=ruby3.4, got {conf.get('Runtime')!r}"
    return {"name": name, "arn": out["FunctionArn"]}


def _queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url), "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _drain(sqs, url) -> list:
    out = []
    while True:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        msgs = resp.get("Messages", [])
        if not msgs:
            return out
        for m in msgs:
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
