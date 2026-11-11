"""lambda-putevents-missing-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-putevents-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role lacks events:PutEvents gets AccessDeniedException with its exact message and
    no rule fires, while the same code with the permission puts an event the rule delivers to SQS."""
    lam = ctx.client("lambda")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue = _create_queue(ctx)
    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": ["sim2real.deniedPut"], "detail-type": ["ShouldRoute"]}
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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

    handler_code = (
        "import boto3, json\n"
        "from botocore.exceptions import ClientError\n"
        "def handler(event, context):\n"
        "    client = boto3.client('events')\n"
        "    try:\n"
        "        client.put_events(Entries=[{\n"
        "            'Source': 'sim2real.deniedPut',\n"
        "            'DetailType': 'ShouldRoute',\n"
        "            'Detail': json.dumps(event['detail']),\n"
        "        }])\n"
        "        return {'ok': True}\n"
        "    except ClientError as e:\n"
        "        return {'ok': False, 'errorCode': e.response['Error']['Code'],\n"
        "                'message': e.response['Error'].get('Message')}\n"
    )

    # --- Negative path: role with no EventBridge permissions.
    bare_role_arn = _create_role(ctx, "lambda.amazonaws.com")
    bare_fn = _create_function(ctx, bare_role_arn, code=handler_code)

    resp = lam.invoke(
        FunctionName=bare_fn["name"],
        InvocationType="RequestResponse",
        Payload=json.dumps({"detail": {"attempt": 1}}).encode(),
    )
    payload = json.loads(resp["Payload"].read())
    assert payload["ok"] is False, f"expected put_events to be denied, got: {payload}"
    assert payload["errorCode"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got: {payload['errorCode']!r}"
    )
    bare_role = bare_role_arn.rsplit("/", 1)[1]
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{bare_role}/{bare_fn['name']} is not authorized "
        f"to perform: events:PutEvents on resource: arn:aws:events:{ctx.region}:{ctx.account}:"
        "event-bus/default because no identity-based policy allows the events:PutEvents action"
    )
    assert payload["message"] == expected, f"expected {expected!r}, got {payload['message']!r}"

    # Effect is absent: the downstream rule never fired.
    absent = _drain(sqs, queue["url"], wait=5)
    assert absent == [], f"expected no delivery for a denied put_events, got: {absent}"

    # --- Positive control: identical code, role WITH events:PutEvents.
    good_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policies={
            "put-events": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}],
            }
        },
    )
    good_fn = _create_function(ctx, good_role_arn, code=handler_code)

    resp2 = lam.invoke(
        FunctionName=good_fn["name"],
        InvocationType="RequestResponse",
        Payload=json.dumps({"detail": {"attempt": 2}}).encode(),
    )
    payload2 = json.loads(resp2["Payload"].read())
    assert payload2["ok"] is True, f"expected put_events to succeed with the grant, got: {payload2}"

    messages = _poll_until(
        lambda: _drain(sqs, queue["url"]),
        lambda msgs: len(msgs) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )
    body = json.loads(messages[0]["Body"])
    assert body["detail"] == {"attempt": 2}, f"expected the delivered detail to match, got: {body}"


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
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags={"sim2real:managed": "true"},
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
    url = sqs.create_queue(QueueName=name, Attributes=attrs, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
