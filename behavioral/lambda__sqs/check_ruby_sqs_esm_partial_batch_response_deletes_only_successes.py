"""ruby-sqs-esm-partial-batch-response-deletes-only-successes."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ruby-sqs-esm-partial-batch-response-deletes-only-successes"
GROUP = "event-propagation"
SERVICES = ["lambda", "sqs"]

_HANDLER = """\
require 'json'
require 'aws-sdk-sqs'

def lambda_handler(event:, context:)
  sqs = Aws::SQS::Client.new
  ids = event['Records'].map { |r| r['messageId'] }
  bodies = event['Records'].map { |r| r['body'] }
  sqs.send_message(
    queue_url: ENV['OBSERVE_QUEUE_URL'],
    message_body: { 'ids' => ids, 'bodies' => bodies }.to_json
  )
  failures = event['Records']
             .select { |r| r['body'].start_with?('FAIL') }
             .map { |r| { 'itemIdentifier' => r['messageId'] } }
  { 'batchItemFailures' => failures }
end
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ruby3.3 handler's batchItemFailures makes the SQS event source mapping delete only the
    successfully processed message in a batch and leaves the one it names on the queue for
    redelivery.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-errorhandling.html
    """
    sqs = ctx.client("sqs")
    src = _queue(ctx, VisibilityTimeout="6")
    observe = _queue(ctx)

    ok_id = sqs.send_message(QueueUrl=src["url"], MessageBody="ok-message")["MessageId"]
    fail_id = sqs.send_message(QueueUrl=src["url"], MessageBody="FAIL-message")["MessageId"]

    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage",
                                       "sqs:GetQueueAttributes"], "Resource": src["arn"]},
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": observe["arn"]},
    ])
    fn = _function(ctx, role["arn"], _HANDLER, "lambda_function.rb",
                   "lambda_function.lambda_handler", "ruby3.3",
                   env={"OBSERVE_QUEUE_URL": observe["url"]}, timeout=5)

    esm = _mapping(ctx, EventSourceArn=src["arn"], FunctionName=fn["name"], BatchSize=10,
                   FunctionResponseTypes=["ReportBatchItemFailures"])
    uuid = esm["UUID"]

    seen: list = []

    def _drained():
        seen.extend(_drain_observations(sqs, observe["url"]))
        return seen

    all_ids = lambda: {i for o in seen for i in o["ids"]}
    _poll(ctx, _drained, lambda _obs: {ok_id, fail_id} <= all_ids(), timeout_s=90,
          what="the handler reports having seen both the ok and the failed messageId")
    all_bodies = {b for o in seen for b in o["bodies"]}
    assert {"ok-message", "FAIL-message"} <= all_bodies, (
        f"the handler's own reports of what it received were {seen!r}")

    def _queue_total():
        attrs = sqs.get_queue_attributes(
            QueueUrl=src["url"],
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        return int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])

    total = _poll(ctx, _queue_total, lambda t: t == 1, timeout_s=60,
                  what="the successfully processed message is deleted, leaving one in the queue")
    assert total == 1, f"expected exactly 1 message left in the source queue, saw {total}"

    ctx.client("lambda").delete_event_source_mapping(UUID=uuid)
    _poll(ctx, lambda: _try_get_mapping(ctx, uuid), lambda s: s is None, timeout_s=60,
          what="the deleted event source mapping stops being readable")

    def _receive_remaining():
        return sqs.receive_message(
            QueueUrl=src["url"], MaxNumberOfMessages=10, VisibilityTimeout=0,
            AttributeNames=["ApproximateReceiveCount"], WaitTimeSeconds=5,
        ).get("Messages", [])

    remaining = _poll(ctx, _receive_remaining, lambda msgs: len(msgs) > 0, timeout_s=30,
                      what="the one remaining message becomes receivable once the mapping stopped")
    # A VisibilityTimeout=0 peek does not consume the message, so SQS's at-least-once delivery
    # can hand back more than one copy of the same logical message in a single receive; identify
    # it by MessageId rather than asserting on the raw, unconsumed receive count.
    by_id = {m["MessageId"]: m for m in remaining}
    assert len(by_id) == 1, f"expected exactly 1 distinct message left in the queue, got {remaining!r}"
    only = next(iter(by_id.values()))
    assert only["Body"] == "FAIL-message", (
        f"the message left in the queue must be the failed one, got {only['Body']!r}")
    recv_count = max(int(m["Attributes"]["ApproximateReceiveCount"]) for m in remaining)
    assert recv_count >= 2, (
        f"the failed message must have been redelivered (receive count >= 2), got {recv_count}")


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


def _zip(code: str, filename: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _execution_role(ctx, statements) -> dict:
    """A Lambda execution role holding exactly ``statements`` and no logs permission at all."""
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


def _function(ctx, role_arn, code, filename, handler, runtime, *, env=None, timeout=30, memory=128) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": runtime, "Handler": handler, "Role": role_arn,
              "Code": {"ZipFile": _zip(code, filename)}, "Timeout": timeout, "MemorySize": memory,
              "Tags": {"sim2real": CHECK}}
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
    assert conf["Runtime"] == runtime, f"expected Runtime={runtime!r}, got {conf.get('Runtime')!r}"
    return {"name": name, "arn": out["FunctionArn"]}


def _mapping(ctx, **kwargs) -> dict:
    """CreateEventSourceMapping through the role-permission propagation window; a genuine
    permission rejection, not that window, raises immediately."""
    lam = ctx.client("lambda")

    def create():
        try:
            return lam.create_event_source_mapping(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code") == "InvalidParameterValueException"
                    and "does not have permissions" in err.get("Message", "")):
                return None
            raise

    esm = _poll(ctx, create, lambda r: r is not None, timeout_s=90,
                what="CreateEventSourceMapping accepts the fresh execution role")
    uuid = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    want = "Enabled" if kwargs.get("Enabled", True) else "Disabled"
    _poll(ctx, lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == want,
          timeout_s=120, what=f"mapping {uuid} reaches {want}")
    return esm


def _try_get_mapping(ctx, uuid):
    try:
        return ctx.client("lambda").get_event_source_mapping(UUID=uuid)["State"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _queue(ctx, **attrs) -> dict:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-")
    url = sqs.create_queue(QueueName=name, Attributes={k: str(v) for k, v in attrs.items()},
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url), "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _drain_observations(sqs, url) -> list:
    """Every invocation's {ids, bodies} report the handler sent, deleted once read."""
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
