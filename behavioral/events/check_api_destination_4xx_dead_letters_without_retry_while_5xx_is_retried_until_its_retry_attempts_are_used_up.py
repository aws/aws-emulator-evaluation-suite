"""api-destination-4xx-dead-letters-without-retry-while-5xx-is-retried-until-its-retry-attempts-are-used-up."""
from __future__ import annotations

import io
import json
import secrets
import time
import urllib.parse
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-destination-4xx-dead-letters-without-retry-while-5xx-is-retried-until-its-retry-attempts-are-used-up"
GROUP = "api-destination"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 360.0
_RETRIES = 1


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """For one event sent to two API destinations differing only in status, the 400 endpoint's
    event is dead-lettered without retry (INVALID_PARAMETER), while the 500 endpoint is retried
    until MaximumRetryAttempts (1) is used up and its dead letter records the exhausted retries."""
    events = ctx.client("events")
    key_value = secrets.token_urlsafe(32)
    base, capture_url = _https_endpoint(ctx, "x-sim2real-key", key_value)
    dlq_url, dlq_arn = _create_queue(ctx, "sim2real-behav-dlq-", events_may_send=True)
    _, conn_arn = _create_connection(ctx, events, "API_KEY", {
        "ApiKeyAuthParameters": {"ApiKeyName": "x-sim2real-key", "ApiKeyValue": key_value}})
    dests = {code: _create_destination(ctx, events, conn_arn, f"{base}/s{code}") for code in ("400", "500")}
    role_arn = _role(ctx, "events.amazonaws.com", ["events:InvokeApiDestination"], list(dests.values()))

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.apidest.")
    rule, rule_arn = _create_rule(ctx, events, bus, {"source": [source]})
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": f"s{code}", "Arn": arn, "RoleArn": role_arn, "DeadLetterConfig": {"Arn": dlq_arn},
         "RetryPolicy": {"MaximumRetryAttempts": _RETRIES, "MaximumEventAgeInSeconds": 900}}
        for code, arn in dests.items()])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    sent: set[str] = set()
    requests: list[dict] = []
    dead: list[dict] = []

    def _event_with_both_letters() -> str | None:
        # Only an event the 400 endpoint actually received is graded: one published before the
        # just-created role was usable is dead-lettered for a different reason.
        for eid in sent:
            if not _seen(requests, {eid}, "/s400"):
                continue
            codes = {d["attrs"].get("TARGET_ARN") for d in dead if d["body"].get("id") == eid}
            if codes >= set(dests.values()):
                return eid
        return None

    wait_s = _budget_s(ctx, _DELIVERY_TIMEOUT_S)
    deadline = time.monotonic() + wait_s
    next_put = 0.0
    while time.monotonic() < deadline and _event_with_both_letters() is None:
        if time.monotonic() >= next_put and not _seen(requests, sent, "/s400"):
            # Re-publish until the endpoint has seen one event: a just-created rule, role or
            # destination can drop events until delivery is live.
            resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source,
                                               "DetailType": "status", "Detail": "{}"}])
            assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
            sent.add(resp["Entries"][0]["EventId"])
            next_put = time.monotonic() + 10.0
        requests += _receive(ctx, capture_url)
        dead += _receive(ctx, dlq_url, attrs=True)
    event_id = _event_with_both_letters()
    if event_id is None and _budget_spent(ctx):
        raise TimeoutError("an event dead-lettered by both targets: the run budget ended first; not graded")
    assert event_id is not None, (
        f"no event was dead-lettered by both targets within {wait_s:.0f}s; "
        f"{len(sent)} sent, {len(dead)} dead letter(s), {len(requests)} request(s)"
    )
    requests += _receive(ctx, capture_url)
    letters = {d["attrs"]["TARGET_ARN"]: d["attrs"] for d in dead if d["body"].get("id") == event_id}
    calls = {p: sum(1 for r in requests if r["path"] == p and _body_id(r) == event_id)
             for p in ("/s400", "/s500")}

    four = letters[dests["400"]]
    assert four == {"ERROR_CODE": "INVALID_PARAMETER",
                    "ERROR_MESSAGE": "ApiDestination returned HTTP status 400 with payload: ",
                    "RULE_ARN": rule_arn, "TARGET_ARN": dests["400"]}, (
        f"the 400 target's dead letter is {_shape(four, rule_arn, dests['400'])!r}"
    )
    assert calls["/s400"] >= 1, "the 400 endpoint never received the event it dead-lettered"

    five = letters[dests["500"]]
    assert five == {"ERROR_CODE": "UNKNOWN",
                    "ERROR_MESSAGE": "ApiDestination returned HTTP status 500 with payload: ",
                    "EXHAUSTED_RETRY_CONDITION": "MaximumRetryAttempts",
                    "RETRY_ATTEMPTS": str(_RETRIES),
                    "RULE_ARN": rule_arn, "TARGET_ARN": dests["500"]}, (
        f"the 500 target's dead letter is {_shape(five, rule_arn, dests['500'])!r}"
    )
    assert calls["/s500"] >= 2, (
        f"a 500 must be retried; the endpoint received the event {calls['/s500']} time(s)"
    )


def _body_id(req: dict) -> str | None:
    try:
        return json.loads(req["body"]).get("id")
    except ValueError:
        return None


def _seen(requests: list[dict], sent: set[str], path: str) -> bool:
    return any(r["path"] == path and _body_id(r) in sent for r in requests)


def _shape(attrs: dict, rule_arn: str, target_arn: str) -> dict:
    """The dead-letter attributes with the two ARNs replaced by whether they matched."""
    out = dict(attrs)
    for key, want in (("RULE_ARN", rule_arn), ("TARGET_ARN", target_arn)):
        if key in out:
            out[key] = out[key] == want
    return out


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# The HTTP endpoint is a Lambda function URL that admits only requests carrying this run's
# connection credential (anything else gets a fixed 403) and copies each admitted request's method,
# path, query string, headers (the credential as its sha256 hex), body and arrival time into a
# capture queue. A path ending in
# /s400 or /s500 is answered with that status. Its role has no CloudWatch Logs permissions, so
# the function never creates a log group.

_HANDLER = r'''
import base64, hashlib, hmac, json, os, time, boto3
_sqs = boto3.client("sqs")
def handler(event, context):
    path = event.get("rawPath") or ""
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    if not hmac.compare_digest(headers.get(os.environ["AUTH_HEADER"], "").encode(),
                               os.environ["AUTH_VALUE"].encode()):
        return {"statusCode": 403, "body": ""}
    headers[os.environ["AUTH_HEADER"]] = hashlib.sha256(os.environ["AUTH_VALUE"].encode()).hexdigest()
    http = event.get("requestContext", {}).get("http", {})
    _sqs.send_message(QueueUrl=os.environ["CAPTURE_URL"], MessageBody=json.dumps({
        "t": time.time(), "method": http.get("method"),
        "path": path, "query": event.get("rawQueryString") or "", "headers": headers, "body": body}))
    status = 200
    for code in ("400", "500"):
        if path.endswith("/s" + code):
            status = int(code)
    return {"statusCode": status, "body": ""}
'''


def _zip_handler() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("index.py")
        info.external_attr = 0o644 << 16
        zf.writestr(info, _HANDLER)
    return buf.getvalue()


def _create_queue(ctx, prefix: str, *, events_may_send: bool = False) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    if events_may_send:
        sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
            "Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage", "Resource": arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}}}]})})
    return url, arn


def _role(ctx, principal: str, actions: list[str], resource) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="access", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": actions, "Resource": resource}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="access"))
    return arn


def _https_endpoint(ctx, auth_header: str, auth_value: str) -> tuple[str, str]:
    """(base URL, capture queue URL); only a request whose ``auth_header`` is ``auth_value`` is admitted."""
    lam = ctx.client("lambda")
    capture_url, capture_arn = _create_queue(ctx, "sim2real-behav-cap-")
    role_arn = _role(ctx, "lambda.amazonaws.com", ["sqs:SendMessage"], capture_arn)
    fn = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": _zip_handler()}, Timeout=10,
                Environment={"Variables": {"AUTH_HEADER": auth_header, "AUTH_VALUE": auth_value,
                                           "CAPTURE_URL": capture_url}},
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            # A just-created execution role is not yet assumable by Lambda; nothing to poll.
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    url = lam.create_function_url_config(FunctionName=fn, AuthType="NONE")["FunctionUrl"]
    ctx.on_cleanup(lambda: lam.delete_function_url_config(FunctionName=fn))
    lam.add_permission(FunctionName=fn, StatementId="url", Action="lambda:InvokeFunctionUrl",
                       Principal="*", FunctionUrlAuthType="NONE")
    lam.add_permission(FunctionName=fn, StatementId="invoke", Action="lambda:InvokeFunction",
                       Principal="*", InvokedViaFunctionUrl=True)
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}", capture_url


def _create_connection(ctx, events, auth_type: str, auth: dict) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-conn-")
    arn = events.create_connection(Name=name, AuthorizationType=auth_type,
                                   AuthParameters=auth)["ConnectionArn"]
    ctx.on_cleanup(lambda: events.delete_connection(Name=name))
    deadline = time.monotonic() + 90
    while (state := events.describe_connection(Name=name)["ConnectionState"]) != "AUTHORIZED":
        assert time.monotonic() < deadline, f"the connection is {state!r}, never AUTHORIZED"
        time.sleep(3)
    return name, arn


def _create_destination(ctx, events, conn_arn: str, endpoint: str, method: str = "POST",
                        rate: int = 300) -> str:
    name = ctx.unique_name("sim2real-behav-dest-")
    arn = events.create_api_destination(
        Name=name, ConnectionArn=conn_arn, InvocationEndpoint=endpoint, HttpMethod=method,
        InvocationRateLimitPerSecond=rate)["ApiDestinationArn"]
    ctx.on_cleanup(lambda: events.delete_api_destination(Name=name))
    return arn


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


def _receive(ctx, url: str, *, attrs: bool = False) -> list[dict]:
    sqs = ctx.client("sqs")
    out = []
    for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1,
                                   MessageAttributeNames=["All"]).get("Messages", []):
        body = json.loads(msg["Body"])
        if attrs:
            body = {"body": body, "attrs": {k: v.get("StringValue")
                                            for k, v in msg.get("MessageAttributes", {}).items()}}
        out.append(body)
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
