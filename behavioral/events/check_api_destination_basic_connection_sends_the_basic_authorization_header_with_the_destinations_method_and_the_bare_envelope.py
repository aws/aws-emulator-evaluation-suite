"""api-destination-basic-connection-sends-the-basic-authorization-header-with-the-destinations-method-and-the-bare-envelope."""
from __future__ import annotations

import hashlib
import base64
import io
import json
import secrets
import time
import urllib.parse
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-destination-basic-connection-sends-the-basic-authorization-header-with-the-destinations-method-and-the-bare-envelope"
GROUP = "api-destination"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 180.0


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A BASIC connection's API destination calls the endpoint with the destination's method (PUT),
    a Basic Authorization header from the credentials, no query string and the bare envelope as
    body; an input transformer on a second rule sends the rendered template instead."""
    events = ctx.client("events")
    user, password = "sim2real-user", secrets.token_urlsafe(32)
    want_auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    base, capture_url = _https_endpoint(ctx, "authorization", want_auth)
    _, conn_arn = _create_connection(ctx, events, "BASIC", {
        "BasicAuthParameters": {"Username": user, "Password": password}})
    dest_arn = _create_destination(ctx, events, conn_arn, base + "/basic", method="PUT")
    role_arn = _role(ctx, "events.amazonaws.com", ["events:InvokeApiDestination"], dest_arn)

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.apidest.")
    rule, _ = _create_rule(ctx, events, bus, {"source": [source], "detail-type": ["raw"]})
    shaped_rule, _ = _create_rule(ctx, events, bus, {"source": [source], "detail-type": ["shaped"]})
    for name, extra in ((rule, {}), (shaped_rule, {"InputTransformer": {
            "InputPathsMap": {"m": "$.detail.m", "id": "$.id"},
            "InputTemplate": '{"order": <m>, "event": <id>}'}})):
        put = events.put_targets(Rule=name, EventBusName=bus, Targets=[
            {"Id": "api", "Arn": dest_arn, "RoleArn": role_arn, **extra}])
        assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    marker = ctx.unique_name("m-")
    raw, shaped, ids = _deliver_pair(ctx, events, bus, source, capture_url, marker)
    for label, req in (("raw", raw), ("shaped", shaped)):
        assert (req["method"], req["path"], req["query"]) == ("PUT", "/basic", ""), (
            f"the {label} request was {req['method']!r} to {req['path']!r} query {req['query']!r}"
        )
        assert req["headers"].get("authorization") == _sha256(want_auth), (
            f"the {label} request's Authorization header is "
            f"{'absent' if 'authorization' not in req['headers'] else 'not Basic base64(user:password)'}"
        )
    body = json.loads(raw["body"])
    assert sorted(body) == ["account", "detail", "detail-type", "id", "region", "resources",
                            "source", "time", "version"], f"the raw body carries keys {sorted(body)!r}"
    assert (body["id"], body["source"], body["detail"]) == (ids["raw"], source, {"m": marker}), (
        f"the raw body is not the delivered event: {body!r}"
    )
    assert json.loads(shaped["body"]) == {"order": marker, "event": ids["shaped"]}, (
        f"the transformed body is {shaped['body'][:300]!r}"
    )


def _deliver_pair(ctx, events, bus, source, capture_url, marker):
    """Publish a raw/shaped pair until both reach the endpoint."""
    sent: dict[str, str] = {}
    got: list[dict] = []
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_put = 0.0

    def _find():
        raw = shaped = None
        for req in got:
            try:
                b = json.loads(req["body"])
            except ValueError:
                continue
            if b.get("id") in sent and sent[b["id"]] == "raw":
                raw = (req, b["id"])
            if b.get("event") in sent and sent[b["event"]] == "shaped":
                shaped = (req, b["event"])
        return raw, shaped

    while time.monotonic() < deadline:
        if time.monotonic() >= next_put:
            # A just-created rule, role or destination can drop events until delivery is live.
            resp = events.put_events(Entries=[
                {"EventBusName": bus, "Source": source, "DetailType": kind,
                 "Detail": json.dumps({"m": marker})} for kind in ("raw", "shaped")])
            assert resp["FailedEntryCount"] == 0, f"PutEvents rejected an entry: {resp['Entries']!r}"
            for kind, e in zip(("raw", "shaped"), resp["Entries"]):
                sent[e["EventId"]] = kind
            next_put = time.monotonic() + 20.0
        got += _receive(ctx, capture_url)
        raw, shaped = _find()
        if raw and shaped:
            return raw[0], shaped[0], {"raw": raw[1], "shaped": shaped[1]}
    raise AssertionError(
        f"the raw and transformed events did not both reach the endpoint within "
        f"{_DELIVERY_TIMEOUT_S}s; {len(got)} request(s) captured"
    )


def _sha256(value: str) -> str:
    """The sha256 hex the endpoint captures in place of a credential."""
    return hashlib.sha256(value.encode()).hexdigest()


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
    for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
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
