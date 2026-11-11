"""events-delivery-and-failure-event-age-limit-dead-letters-without-further-attempts."""
from __future__ import annotations

import io
import json
import secrets
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-delivery-and-failure-event-age-limit-dead-letters-without-further-attempts"
GROUP = "error-propagation"
SERVICES = ["events", "lambda", "sqs"]

_AGE_S = 60
_AGE_RETRIES = 185
_HOLD_S = 40
# The endpoint: a Lambda function URL that records every request carrying the connection's API key
# (the event id, via SQS, whose SentTimestamp is the hit time) and answers it HTTP 500 -- a RETRYABLE
# status for API destinations, so only the retry policy decides when EventBridge stops. Any other
# request gets 403.
_ENDPOINT = (
    "import base64, hmac, json, os, boto3\n"
    "sqs = boto3.client('sqs')\n"
    "def handler(event, context):\n"
    "    hdrs = {k.lower(): v for k, v in (event.get('headers') or {}).items()}\n"
    "    if not hmac.compare_digest(hdrs.get('x-sim2real', '').encode(), os.environ['API_KEY'].encode()):\n"
    "        return {'statusCode': 403, 'body': ''}\n"
    "    body = event.get('body') or ''\n"
    "    if event.get('isBase64Encoded'):\n"
    "        body = base64.b64decode(body).decode()\n"
    "    try:\n"
    "        eid = json.loads(body).get('id')\n"
    "    except Exception:\n"
    "        eid = None\n"
    "    sqs.send_message(QueueUrl=os.environ['HITS_URL'], MessageBody=json.dumps({'id': eid}))\n"
    "    return {'statusCode': 500, 'body': 'boom'}\n"
)


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-retry-policy.html
@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An event failing with a retryable HTTP 500 under MaximumEventAgeInSeconds=60 (and a large
    retry budget) is dead-lettered by the AGE condition with no later attempt, while a twin rule
    with MaximumRetryAttempts=0 dead-letters after RETRY_ATTEMPTS=0.
    """
    events = ctx.client("events")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    q_hits = _queue(ctx, [])
    role_arn = _lambda_role(ctx, q_hits[1])
    api_key = secrets.token_urlsafe(32)
    fn_name, _ = _function(ctx, role_arn, _ENDPOINT, {"HITS_URL": q_hits[0], "API_KEY": api_key})
    url = lam.create_function_url_config(FunctionName=fn_name, AuthType="NONE")["FunctionUrl"]
    lam.add_permission(FunctionName=fn_name, StatementId="url", Action="lambda:InvokeFunctionUrl",
                       Principal="*", FunctionUrlAuthType="NONE")
    lam.add_permission(FunctionName=fn_name, StatementId="url-invoke", Action="lambda:InvokeFunction",
                       Principal="*", InvokedViaFunctionUrl=True)

    conn_name = ctx.unique_name("sim2real-edf-conn-")
    conn_arn = events.create_connection(
        Name=conn_name, AuthorizationType="API_KEY",
        AuthParameters={"ApiKeyAuthParameters": {"ApiKeyName": "x-sim2real", "ApiKeyValue": api_key}},
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: events.delete_connection(Name=conn_name))
    state = _poll_until(lambda: events.describe_connection(Name=conn_name)["ConnectionState"],
                        lambda s: s in ("AUTHORIZED", "CREATE_FAILED"), timeout_s=90, interval_s=2,
                        description="connection leaving CREATING")
    assert state == "AUTHORIZED", f"connection must be AUTHORIZED, got {state!r}"

    dest_name = ctx.unique_name("sim2real-edf-dest-")
    dest_arn = events.create_api_destination(
        Name=dest_name, ConnectionArn=conn_arn, InvocationEndpoint=url, HttpMethod="POST",
        InvocationRateLimitPerSecond=20,
    )["ApiDestinationArn"]
    ctx.on_cleanup(lambda: events.delete_api_destination(Name=dest_name))
    events_role = _events_role(ctx, dest_arn)

    twin_src = ctx.unique_name("sim2real.edf.twin.")
    age_src = ctx.unique_name("sim2real.edf.age.")
    twin_rule, twin_arn = _rule(ctx, {"source": [twin_src]})
    age_rule, age_arn = _rule(ctx, {"source": [age_src]})
    q_dlq = _queue(ctx, [twin_arn, age_arn])
    for rule, retry in (
        (twin_rule, {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 86400}),
        (age_rule, {"MaximumRetryAttempts": _AGE_RETRIES, "MaximumEventAgeInSeconds": _AGE_S}),
    ):
        r = events.put_targets(Rule=rule, Targets=[{
            "Id": "dest", "Arn": dest_arn, "RoleArn": events_role,
            "DeadLetterConfig": {"Arn": q_dlq[1]}, "RetryPolicy": retry,
        }])
        assert r["FailedEntryCount"] == 0, f"PutTargets failed entries: {r.get('FailedEntries')!r}"

    hits, dlq = [], []  # (event_id, sent_ms), and raw DLQ messages

    def _collect(seconds):
        for m in _drain(sqs, q_hits[0], seconds=seconds):
            hits.append((json.loads(m["Body"]).get("id"), int(m["Attributes"]["SentTimestamp"])))
        dlq.extend(_drain(sqs, q_dlq[0], seconds=1))

    def _emit(source):
        out = events.put_events(Entries=[{
            "Source": source, "DetailType": "Age", "Detail": json.dumps({"nonce": uuid.uuid4().hex}),
        }])
        assert out["FailedEntryCount"] == 0, f"PutEvents rejected the event: {out['Entries']!r}"
        return out["Entries"][0]["EventId"]

    def _dlq_for(event_id):
        return [m for m in dlq if json.loads(m["Body"]).get("id") == event_id]

    # Warm-up barrier + twin control: a fresh API-destination connection first fails with an
    # authentication-details error before reaching the endpoint, so emit until a hit is recorded.
    twin_ids = set()

    def _warm():
        twin_ids.add(_emit(twin_src))
        _collect(3)
        return sorted({i for i, _ in hits} & twin_ids)

    warm = _poll_until(_warm, lambda ids: len(ids) >= 1, timeout_s=150, interval_s=3,
                       description="the endpoint recording a request from the twin rule")
    twin_id = warm[0]
    _poll_until(lambda: (_collect(1), _dlq_for(twin_id))[1], lambda ms: len(ms) >= 1, timeout_s=60,
                interval_s=1, description="the twin event's DLQ copy")
    t_attrs = _attrs(_dlq_for(twin_id)[0])
    assert t_attrs.get("EXHAUSTED_RETRY_CONDITION") == "MaximumRetryAttempts", f"twin DLQ attrs {t_attrs!r}"
    assert t_attrs.get("RETRY_ATTEMPTS") == "0", f"twin DLQ attrs {t_attrs!r}"
    assert "HTTP status 500" in (t_attrs.get("ERROR_MESSAGE") or ""), f"twin DLQ attrs {t_attrs!r}"

    # The age-limited event.
    age_id = _emit(age_src)
    _poll_until(lambda: (_collect(2), _dlq_for(age_id))[1], lambda ms: len(ms) >= 1,
                timeout_s=_AGE_S + 90, interval_s=1, description="the age-limited event's DLQ copy")
    msg = _dlq_for(age_id)[0]
    dlq_sent_ms = int(msg["Attributes"]["SentTimestamp"])
    a = _attrs(msg)
    assert a.get("EXHAUSTED_RETRY_CONDITION") == "MaximumEventAgeInSeconds", (
        f"an event older than MaximumEventAgeInSeconds must be ended by the AGE condition, got {a!r}"
    )
    assert int(a.get("RETRY_ATTEMPTS", "-1")) < _AGE_RETRIES, f"retry budget cannot have run out: {a!r}"
    assert "HTTP status 500" in (a.get("ERROR_MESSAGE") or ""), f"expected the endpoint's 500, got {a!r}"
    assert a.get("RULE_ARN") == age_arn and a.get("TARGET_ARN") == dest_arn, f"DLQ attrs {a!r}"

    # Attempt counts are not asserted: delivery is at-least-once. 1 s allows for clock skew.
    hold_end = time.monotonic() + _HOLD_S
    while time.monotonic() < hold_end:
        _collect(3)
    age_hits = [ms for i, ms in hits if i == age_id]
    assert age_hits, "the age-limited event must have reached the endpoint at least once"
    late = [ms - dlq_sent_ms for ms in age_hits if ms > dlq_sent_ms + 1000]
    assert late == [], (
        f"no attempt may follow the age-limit dead-letter; hits {late!r} ms after the DLQ send"
    )


def _attrs(msg):
    return {k: v.get("StringValue") for k, v in msg.get("MessageAttributes", {}).items()}


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) holds; raise on the deadline."""
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
    """A queue; when rule_arns is non-empty, EventBridge may deliver to it from exactly those rules."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-edf-q-"), tags={"sim2real": "events-delivery-and-failure"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    if rule_arns:
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
    """Receive-and-delete every message for `seconds`."""
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


def _role(ctx, service, policy_doc):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-edf-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": "events-delivery-and-failure"}])["Role"]["Arn"]

    def _delete():
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="inline")
        except iam.exceptions.NoSuchEntityException:
            pass
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_delete)
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy_doc))
    return arn


def _lambda_role(ctx, send_to_queue_arn):
    """Execution role: sqs:SendMessage to one queue, and nothing else (no CloudWatch Logs)."""
    return _role(ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": send_to_queue_arn}]})


def _events_role(ctx, dest_arn):
    return _role(ctx, "events.amazonaws.com", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "events:InvokeApiDestination", "Resource": dest_arn}]})


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
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
                lambda s: s == "Active", timeout_s=90, interval_s=2, description=f"function {name} Active")
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
