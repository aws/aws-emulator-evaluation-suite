"""ruby-ddb-stream-new-and-old-image-reach-the-handler."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ruby-ddb-stream-new-and-old-image-reach-the-handler"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda", "sqs"]

_HANDLER = """\
require 'json'
require 'aws-sdk-sqs'

def lambda_handler(event:, context:)
  sqs = Aws::SQS::Client.new
  event['Records'].each do |record|
    ddb = record['dynamodb']
    sqs.send_message(
      queue_url: ENV['OBSERVE_QUEUE_URL'],
      message_body: {
        'eventName' => record['eventName'],
        'keys' => ddb['Keys'],
        'newImage' => ddb['NewImage'],
        'oldImage' => ddb['OldImage']
      }.to_json
    )
  end
  { 'ok' => true }
end
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Under StreamViewType NEW_AND_OLD_IMAGES, a ruby3.3 handler receives an INSERT record with
    only a NewImage, a MODIFY record with both typed images, and a REMOVE record with only an
    OldImage, each keyed by the item's primary key.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/example_serverless_DynamoDB_Lambda_section.html
    """
    ddb = ctx.client("dynamodb")
    observe = _queue(ctx)
    table = _table(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords",
                                       "dynamodb:GetShardIterator", "dynamodb:ListStreams"],
         "Resource": table["stream_arn"]},
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": observe["arn"]},
    ])
    fn = _function(ctx, role["arn"], _HANDLER, env={"OBSERVE_QUEUE_URL": observe["url"]})
    _mapping(ctx, EventSourceArn=table["stream_arn"], FunctionName=fn["name"],
             StartingPosition="TRIM_HORIZON", BatchSize=10)

    k = ctx.unique_name("item-")
    v1 = {"pk": {"S": k}, "n": {"N": "1"}}
    v2 = {"pk": {"S": k}, "n": {"N": "2"}}
    ddb.put_item(TableName=table["name"], Item=v1)
    ddb.put_item(TableName=table["name"], Item=v2)
    ddb.delete_item(TableName=table["name"], Key={"pk": {"S": k}})

    sqs = ctx.client("sqs")

    def mine():
        return [r for r in _drain(sqs, observe["url"]) if r.get("keys") == {"pk": {"S": k}}]

    seen: list = []

    def _probe():
        seen.extend(mine())
        return seen

    recs = _poll(ctx, _probe, lambda rs: len(rs) >= 3, cap_s=180, interval_s=2,
                what="three stream records for the item reach the ruby handler")
    by_name = {r["eventName"]: r for r in recs}
    assert set(by_name) == {"INSERT", "MODIFY", "REMOVE"}, f"eventNames seen: {sorted(by_name)!r}"

    ins, mod, rem = by_name["INSERT"], by_name["MODIFY"], by_name["REMOVE"]
    assert ins["newImage"] == v1, f"INSERT NewImage was {ins['newImage']!r}"
    assert ins["oldImage"] is None, f"INSERT must carry no OldImage, got {ins['oldImage']!r}"
    assert mod["newImage"] == v2, f"MODIFY NewImage was {mod['newImage']!r}"
    assert mod["oldImage"] == v1, f"MODIFY OldImage was {mod['oldImage']!r}"
    assert rem["newImage"] is None, f"REMOVE must carry no NewImage, got {rem['newImage']!r}"
    assert rem["oldImage"] == v2, f"REMOVE OldImage was {rem['oldImage']!r}"


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


def _poll(ctx, probe, done, *, cap_s, interval_s, what):
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")


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
    kwargs = {"FunctionName": name, "Runtime": "ruby3.3", "Handler": "lambda_function.lambda_handler",
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

    out = _poll(ctx, create, lambda r: r is not None, cap_s=90, interval_s=2,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"), cap_s=90, interval_s=2,
                 what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    assert conf["Runtime"] == "ruby3.3", f"expected Runtime=ruby3.3, got {conf.get('Runtime')!r}"
    return {"name": name, "arn": out["FunctionArn"]}


def _mapping(ctx, **kwargs) -> dict:
    lam = ctx.client("lambda")

    def create():
        try:
            return lam.create_event_source_mapping(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    esm = _poll(ctx, create, lambda r: r is not None, cap_s=90, interval_s=2,
                what="CreateEventSourceMapping accepts the fresh execution role")
    uuid = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    _poll(ctx, lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == "Enabled",
          cap_s=120, interval_s=2, what=f"mapping {uuid} reaches Enabled")
    return esm


def _table(ctx) -> dict:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-xsvc-t-")
    ddb.create_table(TableName=name, BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                     StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    desc = ddb.describe_table(TableName=name)["Table"]
    return {"name": name, "arn": desc["TableArn"], "stream_arn": desc["LatestStreamArn"]}


def _queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-")
    sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})
    url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url), "AWS.SimpleQueueService.NonExistentQueue"))
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
