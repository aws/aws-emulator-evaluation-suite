"""eventbridge-lambda-target-missing-permission-dlq."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-lambda-target-missing-permission-dlq"
GROUP = "overly-permissive"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda target without an invoke grant is never invoked; the event goes to the target
    DLQ with ERROR_CODE NO_PERMISSIONS and the target ARN, and once granted the same target
    receives the next event."""
    events = ctx.client("events")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    out_queue = _create_queue(ctx)
    dlq = _create_queue(ctx)

    role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policies={
            "forward-to-sqs": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": out_queue["arn"]}
                ],
            }
        },
    )
    fn = _create_function(
        ctx,
        role_arn,
        code=(
            "import boto3, json, os\n"
            "def handler(event, context):\n"
            "    sqs = boto3.client('sqs')\n"
            "    sqs.send_message(QueueUrl=os.environ['OUT_URL'], MessageBody=json.dumps(event))\n"
            "    return {'ok': True}\n"
        ),
        env={"OUT_URL": out_queue["url"]},
    )

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": ["sim2real.dlqtest"], "detail-type": ["Attempt"]}
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    dlq_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": dlq["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=dlq["url"], Attributes={"Policy": json.dumps(dlq_policy)})

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {
                "Id": "t1",
                "Arn": fn["arn"],
                "DeadLetterConfig": {"Arn": dlq["arn"]},
                # Without a tight retry policy, EventBridge's default behavior is to retry a
                # failing invocation for up to 24h/185 attempts before giving up to the DLQ --
                # far longer than this check can wait. Force near-immediate DLQ routing.
                "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            }
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    # --- Negative path: no resource-based policy on the function yet.
    # Re-emit periodically: it can take a moment for the rule/target config to be fully
    # effective, and we want the DLQ delivery, not just one fired attempt.
    def _emit_and_drain_dlq():
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.dlqtest",
                    "DetailType": "Attempt",
                    "Detail": json.dumps({"attempt": 1}),
                }
            ]
        )
        return _drain(sqs, dlq["url"])

    dlq_messages = _poll_until(
        _emit_and_drain_dlq,
        lambda msgs: len(msgs) >= 1,
        timeout_s=90.0,
        interval_s=5.0,
    )
    attrs = dlq_messages[0]["MessageAttributes"]
    got_error_code = attrs["ERROR_CODE"]["StringValue"]
    assert got_error_code == "NO_PERMISSIONS", (
        f"expected DLQ ERROR_CODE=NO_PERMISSIONS, got {got_error_code!r}"
    )
    got_target_arn = attrs["TARGET_ARN"]["StringValue"]
    assert got_target_arn == fn["arn"], (
        f"expected DLQ TARGET_ARN={fn['arn']!r}, got {got_target_arn!r}"
    )

    # Effect is absent: the function was never invoked, so nothing was forwarded downstream.
    leaked = _drain(sqs, out_queue["url"], wait=5)
    assert leaked == [], (
        f"expected no messages forwarded to the out queue without invoke permission, got {leaked!r}"
    )

    # --- Positive control: grant the permission and retry with a distinct payload.
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId=ctx.unique_name("sim2real-stmt-"),
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    # The new resource-based policy on the function can take a few seconds to propagate;
    # re-emit the event periodically until the invocation actually goes through rather than
    # relying on a single put_events call landing right after add_permission returns.
    def _emit_and_drain_out():
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.dlqtest",
                    "DetailType": "Attempt",
                    "Detail": json.dumps({"attempt": 2}),
                }
            ]
        )
        return _drain(sqs, out_queue["url"])

    out_messages = _poll_until(
        _emit_and_drain_out,
        lambda msgs: len(msgs) >= 1,
        timeout_s=90.0,
        interval_s=5.0,
    )
    body = json.loads(out_messages[0]["Body"])
    got_detail = body["detail"]
    assert got_detail == {"attempt": 2}, (
        f"expected delivered detail {{'attempt': 2}}, got {got_detail!r}"
    )


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
    resp = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=max_msgs, WaitTimeSeconds=wait, MessageAttributeNames=["All"]
    )
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
                Tags={"sim2real": "true"},
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
    url = sqs.create_queue(QueueName=name, Attributes=attrs, tags={"sim2real": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
