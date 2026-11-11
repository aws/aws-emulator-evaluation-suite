"""ruby-s3-object-created-notification-record-reaches-the-handler."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ruby-s3-object-created-notification-record-reaches-the-handler"
GROUP = "event-propagation"
SERVICES = ["lambda", "s3", "sqs"]

_HANDLER = """\
require 'json'
require 'aws-sdk-sqs'
require 'uri'

def lambda_handler(event:, context:)
  sqs = Aws::SQS::Client.new
  event['Records'].each do |record|
    s3 = record['s3']
    sqs.send_message(
      queue_url: ENV['OBSERVE_QUEUE_URL'],
      message_body: {
        'eventName' => record['eventName'],
        'eventSource' => record['eventSource'],
        'bucket' => s3['bucket']['name'],
        'key' => URI.decode_www_form_component(s3['object']['key']),
        'size' => s3['object']['size']
      }.to_json
    )
  end
  { 'ok' => true }
end
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An S3 ObjectCreated notification invokes a ruby4.0 handler with a Records entry carrying
    the exact bucket name, URL-decoded key and byte size of the object that was put.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-s3.html
    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html
    """
    bucket = _bucket(ctx)
    observe = _queue(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": observe["arn"]},
    ])
    fn = _function(ctx, role["arn"], _HANDLER, env={"OBSERVE_QUEUE_URL": observe["url"]})

    lam = ctx.client("lambda")
    lam.add_permission(FunctionName=fn["name"], StatementId="s3invoke",
                       Action="lambda:InvokeFunction", Principal="s3.amazonaws.com",
                       SourceArn=f"arn:aws:s3:::{bucket['name']}", SourceAccount=ctx.account)

    s3 = ctx.client("s3")
    body = b"sim2real-ruby-s3-event-payload"
    notification = {"LambdaFunctionConfigurations": [
        {"LambdaFunctionArn": fn["arn"], "Events": ["s3:ObjectCreated:*"]}]}
    _put_notification_after_permission(ctx, s3, bucket["name"], notification,
                                        timeout_s=_budget_s(ctx, 90.0))

    sqs = ctx.client("sqs")

    # A PutObject sent before PutBucketNotificationConfiguration has armed is DROPPED and never
    # redelivered, so put a fresh key every round rather than probing a single upload.
    uploaded: list[str] = []

    def _upload_and_receive():
        key = f"orders/needs encoding {len(uploaded) + 1}.txt"
        uploaded.append(key)
        s3.put_object(Bucket=bucket["name"], Key=key, Body=body)
        return _receive_one(sqs, observe["url"])

    record = _poll(ctx, _upload_and_receive, lambda r: r is not None,
                   timeout_s=_budget_s(ctx, 90), what="the handler relays the Records entry it received")
    assert record["bucket"] == bucket["name"], f"s3.bucket.name was {record['bucket']!r}"
    assert record["key"] in uploaded, (
        f"s3.object.key must be URL-decoded back to one of {uploaded!r}, got {record['key']!r}")
    assert record["size"] == len(body), f"s3.object.size was {record['size']!r}, expected {len(body)}"
    assert record["eventName"] == "ObjectCreated:Put", (
        f"a PutObject must be reported as ObjectCreated:Put, got {record['eventName']!r}")
    assert record["eventSource"] == "aws:s3", f"eventSource was {record['eventSource']!r}"


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
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


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
    kwargs = {"FunctionName": name, "Runtime": "ruby4.0", "Handler": "lambda_function.lambda_handler",
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

    out = _poll(ctx, create, lambda r: r is not None, timeout_s=_budget_s(ctx, 90),
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"), timeout_s=_budget_s(ctx, 90),
                 what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    assert conf["Runtime"] == "ruby4.0", f"expected Runtime=ruby4.0, got {conf.get('Runtime')!r}"
    return {"name": name, "arn": out["FunctionArn"]}


def _bucket(ctx) -> dict:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-bkt-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(_teardown(lambda: _empty_and_delete_bucket(ctx, name), "NoSuchBucket"))
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _queue(ctx) -> dict:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-")
    sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})
    url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url), "AWS.SimpleQueueService.NonExistentQueue"))
    return {"name": name, "url": url, "arn": arn}


def _receive_one(sqs, url):
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
    msgs = resp.get("Messages", [])
    if not msgs:
        return None
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msgs[0]["ReceiptHandle"])
    return json.loads(msgs[0]["Body"])


def _put_notification_after_permission(ctx, s3, bucket, notification, timeout_s=90.0):
    """PutBucketNotificationConfiguration, retried through the add_permission propagation window:
    S3 refuses a config naming a function it cannot yet confirm is invokable by it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s3.put_bucket_notification_configuration(
                Bucket=bucket, NotificationConfiguration=notification)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidArgument",):
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        "PutBucketNotificationConfiguration: the run budget ended first; "
                        "not graded"
                    ) from exc
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
