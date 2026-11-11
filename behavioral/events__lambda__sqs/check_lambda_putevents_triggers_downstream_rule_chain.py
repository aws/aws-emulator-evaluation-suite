"""lambda-putevents-triggers-downstream-rule-chain."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-putevents-triggers-downstream-rule-chain"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "sqs"]

_MANAGED_TAG = {"sim2real:managed": "true"}
_MANAGED_TAG_KV = [{"Key": k, "Value": v} for k, v in _MANAGED_TAG.items()]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function that calls events:PutEvents from inside its handler (via the AWS SDK)
    actually emits a real EventBridge event: a rule matching that event delivers it to an SQS
    target, proving the full Lambda -> EventBridge -> SQS chain works end to end."""
    lam = ctx.client("lambda")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue = _create_queue(ctx)

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": ["sim2real.viaLambda"], "detail-type": ["TriggeredByLambda"]}
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), Tags=_MANAGED_TAG_KV
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policies={
            "put-events": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}],
            }
        },
    )
    fn = _create_function(
        ctx,
        role_arn,
        code=(
            "import boto3, json\n"
            "def handler(event, context):\n"
            "    client = boto3.client('events')\n"
            "    resp = client.put_events(Entries=[{\n"
            "        'Source': 'sim2real.viaLambda',\n"
            "        'DetailType': 'TriggeredByLambda',\n"
            "        'Detail': json.dumps(event['detail']),\n"
            "    }])\n"
            "    return {'FailedEntryCount': resp['FailedEntryCount']}\n"
        ),
    )

    detail = {"orderId": "via-lambda-1"}
    resp = lam.invoke(
        FunctionName=fn["name"],
        InvocationType="RequestResponse",
        Payload=json.dumps({"detail": detail}).encode(),
    )
    assert resp.get("FunctionError") is None, f"lambda invoke reported an error: {resp}"
    payload = json.loads(resp["Payload"].read())
    assert payload["FailedEntryCount"] == 0, f"put_events reported failures: {payload}"

    messages = _poll_until(
        lambda: _drain(sqs, queue["url"]),
        lambda msgs: len(msgs) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )
    body = json.loads(messages[0]["Body"])
    assert body["source"] == "sim2real.viaLambda", f"unexpected source: {body!r}"
    assert body["detail-type"] == "TriggeredByLambda", f"unexpected detail-type: {body!r}"
    assert body["detail"] == detail, f"expected detail {detail!r}, got {body.get('detail')!r}"


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _drain(sqs, url, max_msgs=10, wait=2):
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=max_msgs, WaitTimeSeconds=wait)
    return resp.get("Messages", [])


def _create_role(ctx, trust_service, inline_policies=None, managed_arns=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAG_KV
    )["Role"]["Arn"]

    def _cleanup():
        for pname in list((inline_policies or {}).keys()):
            try:
                iam.delete_role_policy(RoleName=name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for marn in (managed_arns or []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=marn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for marn in (managed_arns or []):
        iam.attach_role_policy(RoleName=name, PolicyArn=marn)
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_arn


def _create_function(ctx, role_arn, code, handler="handler.handler", env=None, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", code)
    zip_bytes = buf.getvalue()
    deadline = time.monotonic() + 40.0
    resp = None
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags=_MANAGED_TAG,
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2,
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_queue(ctx, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    suffix = ".fifo" if fifo else ""
    name = ctx.unique_name("sim2real-q-") + suffix
    attrs = dict(extra_attrs or {})
    if fifo:
        attrs["FifoQueue"] = "true"
        attrs.setdefault("ContentBasedDeduplication", "true")
    url = sqs.create_queue(QueueName=name, Attributes=attrs, tags=dict(_MANAGED_TAG))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
