"""api-destination-oauth-connection-fetches-a-client-credentials-token-and-sends-it-as-the-bearer-header."""
from __future__ import annotations

import hashlib
import io
import json
import secrets
import time
import urllib.parse
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-destination-oauth-connection-fetches-a-client-credentials-token-and-sends-it-as-the-bearer-header"
GROUP = "api-destination"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 180.0


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An OAUTH_CLIENT_CREDENTIALS connection POSTs its OAuthHttpParameters and a form body of
    exactly client_id, client_secret and scope to the token endpoint, becomes AUTHORIZED, and
    the event request carries `Authorization: Bearer <issued token>` with the envelope as body."""
    events = ctx.client("events")
    token = secrets.token_urlsafe(32)
    client_id, secret = "sim2real-client", secrets.token_urlsafe(32)
    base, capture_url = _https_endpoint(ctx, token, secret)
    _, conn_arn = _create_connection(ctx, events, "OAUTH_CLIENT_CREDENTIALS", {
        "OAuthParameters": {
            "ClientParameters": {"ClientID": client_id, "ClientSecret": secret},
            "AuthorizationEndpoint": base + "/token", "HttpMethod": "POST",
            "OAuthHttpParameters": {
                "BodyParameters": [{"Key": "scope", "Value": "orders/write", "IsValueSecret": False}],
                "HeaderParameters": [{"Key": "x-oauth-h", "Value": "oh", "IsValueSecret": False}],
                "QueryStringParameters": [{"Key": "aq", "Value": "a1", "IsValueSecret": False}]}}})
    dest_arn = _create_destination(ctx, events, conn_arn, base + "/api")
    role_arn = _role(ctx, "events.amazonaws.com", ["events:InvokeApiDestination"], dest_arn)

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.apidest.")
    rule, _ = _create_rule(ctx, events, bus, {"source": [source]})
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "api", "Arn": dest_arn, "RoleArn": role_arn}])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    reqs: list[dict] = []
    sent: set[str] = set()
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < deadline and not any(
            r["path"] == "/api" and _body_id(r) in sent for r in reqs):
        if time.monotonic() >= next_put:
            # A just-created rule, role or destination can drop events until delivery is live.
            resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source,
                                               "DetailType": "oauth", "Detail": json.dumps({"n": 1})}])
            assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
            sent.add(resp["Entries"][0]["EventId"])
            next_put = time.monotonic() + 20.0
        reqs += _receive(ctx, capture_url)

    token_reqs = [r for r in reqs if r["path"] == "/token"]
    assert token_reqs, "the authorization endpoint never received a token request"
    tr = token_reqs[0]
    assert (tr["method"], tr["query"]) == ("POST", "aq=a1"), (
        f"the token request was {tr['method']!r} with query {tr['query']!r}"
    )
    assert (tr["headers"].get("x-oauth-h"), tr["headers"].get("content-type")) == (
        "oh", "application/x-www-form-urlencoded"), (
        f"the token request carried x-oauth-h={tr['headers'].get('x-oauth-h')!r}, "
        f"content-type={tr['headers'].get('content-type')!r}"
    )
    form = dict(urllib.parse.parse_qsl(tr["body"]))
    assert sorted(form) == ["client_id", "client_secret", "scope"], (
        f"the token request's form fields are {sorted(form)!r}"
    )
    assert (form["client_id"], form["client_secret"] == _sha256(secret), form["scope"]) == (
        client_id, True, "orders/write"), (
        f"the token request sent client_id={form['client_id']!r}, the secret "
        f"{'unchanged' if form['client_secret'] == _sha256(secret) else 'altered'}, scope={form['scope']!r}"
    )

    api = [r for r in reqs if r["path"] == "/api" and _body_id(r) in sent]
    assert api, (
        f"none of {len(sent)} event(s) reached the API within {_DELIVERY_TIMEOUT_S}s; "
        f"{len(reqs)} request(s) captured"
    )
    req = api[0]
    assert req["headers"].get("authorization") == _sha256(f"Bearer {token}"), (
        "the API request's Authorization header is "
        f"{'absent' if 'authorization' not in req['headers'] else 'not Bearer <issued token>'}"
    )
    assert secret not in json.dumps(req), "the client secret was sent to the API endpoint"
    body = json.loads(req["body"])
    assert (body["source"], body["detail-type"], body["detail"]) == (source, "oauth", {"n": 1}), (
        f"the API request body is not the event: {body!r}"
    )


def _body_id(req: dict) -> str | None:
    try:
        return json.loads(req["body"]).get("id")
    except (ValueError, AttributeError):
        return None


def _sha256(value: str) -> str:
    """The sha256 hex the endpoint captures in place of a credential."""
    return hashlib.sha256(value.encode()).hexdigest()


# The HTTP endpoint is a Lambda function URL that admits only requests carrying this run's
# connection credential (anything else gets a fixed 403) and copies each admitted request's method,
# path, query string, headers (the credential as its sha256 hex), body and arrival time into a
# capture queue. A path ending in
# /s400 or /s500 is answered with that status, and one ending in /token with an OAuth token.
# Its role has no CloudWatch Logs permissions, so the function never creates a log group.

_HANDLER = r'''
import base64, hashlib, hmac, json, os, time, boto3, urllib.parse
_sqs = boto3.client("sqs")
def handler(event, context):
    path = event.get("rawPath") or ""
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    if path.endswith("/token"):
        got = urllib.parse.parse_qs(body).get("client_secret", [""])[0]
        want = os.environ["CLIENT_SECRET"]
    else:
        got, want = headers.get("authorization", ""), "Bearer " + os.environ["TOKEN"]
    if not hmac.compare_digest(got.encode(), want.encode()):
        return {"statusCode": 403, "body": ""}
    if path.endswith("/token"):
        body = urllib.parse.urlencode([(k, hashlib.sha256(v.encode()).hexdigest() if k == "client_secret" else v)
                                       for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True)])
    else:
        headers["authorization"] = hashlib.sha256(got.encode()).hexdigest()
    http = event.get("requestContext", {}).get("http", {})
    _sqs.send_message(QueueUrl=os.environ["CAPTURE_URL"], MessageBody=json.dumps({
        "t": time.time(), "method": http.get("method"),
        "path": path, "query": event.get("rawQueryString") or "", "headers": headers, "body": body}))
    if path.endswith("/token"):
        return {"statusCode": 200, "headers": {"content-type": "application/json"},
                "body": json.dumps({"access_token": os.environ.get("TOKEN", ""), "token_type": "Bearer",
                                    "expires_in": 3600})}
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


def _https_endpoint(ctx, token: str, client_secret: str) -> tuple[str, str]:
    """(base URL, capture queue URL); a path ending /token admits ``client_secret`` and answers an
    OAuth client-credentials token response carrying ``token``; other paths admit that bearer."""
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
                Environment={"Variables": {"CAPTURE_URL": capture_url, "TOKEN": token,
                                           "CLIENT_SECRET": client_secret}},
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
