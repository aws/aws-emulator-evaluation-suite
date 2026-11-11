"""ws-connect-event-carries-direction-domain-stage-and-handshake-headers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import textwrap
import time
import urllib.parse
import zipfile
from io import BytesIO

from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ws-connect-event-carries-direction-domain-stage-and-handshake-headers"

GROUP = "websocket-connect-event-shape"

SERVICES = ["apigatewayv2", "iam", "lambda", "logs"]

_PREFIX = "sim2real-behav-"

_STAGE = "dev"

_ROLE_NOT_ASSUMABLE = (
    "InvalidParameterValueException",
    "The role defined for the function cannot be assumed by Lambda.",
)

_CONNECT_HANDLER = """
import json


def lambda_handler(event, context):
    print("EVENT=" + json.dumps(event))
    return {"statusCode": 200}
"""


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, trust_service, inline_policy):
    iam = ctx.client("iam")
    role_name = _name(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return resp["Role"]["Arn"]


def _cleanup_log_group(ctx, log_group_name, timeout_s=60.0, interval_s=2.0):
    """A Lambda's log group is created asynchronously by its first invocation and can still be
    materializing when teardown runs; delete_function never removes it. Retry the delete through
    a bounded window, tolerating a not-yet-created group."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            logs.delete_log_group(logGroupName=log_group_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            if time.monotonic() >= deadline:
                return
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_lambda(ctx, handler_code, permissions=None, timeout=15):
    """Create a Lambda whose role is scoped to logs plus `permissions`, retrying through the IAM
    role-propagation window, then wait for Active. Registers teardown for the role, the function
    and the auto-created /aws/lambda/<name> log group."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    statements.extend(permissions or [])
    role_arn = _create_role(
        ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )

    lam = ctx.client("lambda")
    name = _name(ctx, "fn")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": 128,
        "Tags": dict(_resource_tags()),
    }

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
            if got == _ROLE_NOT_ASSUMABLE:
                return None
            raise

    created = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: _cleanup_log_group(ctx, f"/aws/lambda/{name}"))
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _create_ws_api(ctx):
    v2 = ctx.client("apigatewayv2")
    api_id = v2.create_api(
        Name=_name(ctx, "wsapi"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=_resource_tags(),
    )["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    return api_id


def _ws_endpoint(ctx, api_id, stage):
    """(use_tls, connect_host, connect_port, http_host_header, path) from ctx.api_url."""
    url = urllib.parse.urlsplit(ctx.api_url(api_id, stage, websocket=True))
    use_tls = url.scheme == "wss"
    port = url.port or (443 if use_tls else 80)
    return use_tls, url.hostname, port, url.hostname, url.path or "/"


def _ssl_context(verify):
    """The TLS trust ctx.http_verify names: False -> unverified, a path -> that CA bundle."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _ws_attempt(ctx, api_id, stage, key, raw_query=None, extra_headers=None, timeout_s=20.0):
    """One RFC 6455 handshake with Sec-WebSocket-Key ``key``: (status, head, sock_or_body)."""
    use_tls, host, port, http_host, path = _ws_endpoint(ctx, api_id, stage)
    if raw_query:
        path = f"{path}?{raw_query}"
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if use_tls:
        sock = _ssl_context(ctx.http_verify).wrap_socket(sock, server_hostname=http_host)
    header_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {http_host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    for k, v in (extra_headers or {}).items():
        header_lines.append(f"{k}: {v}")
    req = "\r\n".join(header_lines) + "\r\n\r\n"
    sock.sendall(req.encode())
    sock.settimeout(timeout_s)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head_bytes, _, rest = buf.partition(b"\r\n\r\n")
    head = head_bytes.decode("utf-8", "replace")
    lines = head.splitlines()
    first = lines[0] if lines else ""
    parts = first.split(" ")
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else -1
    if status == 101:
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        got_accept = [
            ln.split(":", 1)[1].strip()
            for ln in lines[1:]
            if ln.lower().startswith("sec-websocket-accept:")
        ]
        assert got_accept == [accept], (
            f"101 upgrade carried no valid Sec-WebSocket-Accept for our key; head was {head!r}"
        )
        return status, head, sock
    content_length = None
    for ln in lines[1:]:
        if ln.lower().startswith("content-length:"):
            content_length = int(ln.split(":", 1)[1].strip())
            break
    body = rest
    if content_length is not None:
        while len(body) < content_length:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
    try:
        sock.close()
    except OSError:
        pass
    return status, head, body.decode("utf-8", "replace")


def _presigned_query(ctx, api_id, stage, extra_params):
    """A fresh execute-api SigV4 query-string presignature carrying `extra_params`."""
    https_url = ctx.api_url(api_id, stage, websocket=False)
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    creds = Credentials(akid, secret, env.get("AWS_SESSION_TOKEN"))
    req = AWSRequest(method="GET", url=https_url, params=dict(extra_params))
    SigV4QueryAuth(creds, "execute-api", ctx.region).add_auth(req)
    return urllib.parse.urlsplit(req.url).query


def _ws_close(sock):
    try:
        code = (1000).to_bytes(2, "big")
        mask = os.urandom(4)
        sock.sendall(b"\x88\x82" + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(code)))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _find_event(ctx, log_group, marker, timeout_s=120.0, interval_s=5.0):
    """The $connect event JSON this run's handshake printed, found by its unique marker."""
    logs = ctx.client("logs")

    def _probe():
        try:
            resp = logs.filter_log_events(logGroupName=log_group, filterPattern='"EVENT="')
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return None
            raise
        for e in resp.get("events", []):
            msg = e["message"]
            if "EVENT=" in msg and marker in msg:
                return json.loads(msg.split("EVENT=", 1)[1].strip())
        return None

    return _poll_until(
        _probe,
        lambda r: r is not None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"the $connect event carrying marker {marker!r} in {log_group}",
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c6",
    "concern:data-plane",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A WebSocket $connect event carries requestContext.messageDirection 'IN', the stage's own
    domainName and stage, and the client's Sec-WebSocket-Key/Version/Extensions handshake headers.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-integration-requests.html
    """
    fn = _create_lambda(ctx, _CONNECT_HANDLER)
    log_group = f"/aws/lambda/{fn['name']}"

    api_id = _create_ws_api(ctx)
    v2 = ctx.client("apigatewayv2")
    integration_id = v2.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationMethod="POST",
        IntegrationUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
            f"{fn['arn']}/invocations"
        ),
    )["IntegrationId"]
    v2.create_route(
        ApiId=api_id,
        RouteKey="$connect",
        Target=f"integrations/{integration_id}",
        AuthorizationType="AWS_IAM",
    )
    v2.create_stage(ApiId=api_id, StageName=_STAGE, AutoDeploy=True)
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=_STAGE))
    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-ws-connect-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/*",
    )

    marker = ctx.unique_name("sim2real-behav-wsconn-")
    query_extensions = "permessage-deflate; client_max_window_bits"
    sent_keys = []

    def _handshake():
        raw_query = _presigned_query(ctx, api_id, _STAGE, {"marker": marker})
        sent_keys.append(base64.b64encode(os.urandom(16)).decode())
        return _ws_attempt(
            ctx,
            api_id,
            _STAGE,
            sent_keys[-1],
            raw_query=raw_query,
            extra_headers={"Sec-WebSocket-Extensions": query_extensions},
        )

    def _probe():
        try:
            return _handshake()
        except OSError as exc:
            return (-1, repr(exc), None)

    # A fresh AWS_IAM route's authorization can still meet a 403 for a short window while it
    # propagates to the edge; each retry carries its own fresh presignature and key. A refused
    # handshake never reaches the integration, so the one logged event is the upgraded one.
    _, _, sock = _poll_until(
        _probe,
        lambda r: r[0] == 101,
        timeout_s=120.0,
        interval_s=5.0,
        description="SigV4-presigned WebSocket handshake upgrading",
    )
    _ws_close(sock)

    event = _find_event(ctx, log_group, marker)
    request_context = event.get("requestContext") or {}

    assert request_context.get("messageDirection") == "IN", (
        f"expected requestContext.messageDirection 'IN' on $connect, got "
        f"{request_context.get('messageDirection')!r}"
    )
    expected_domain = urllib.parse.urlsplit(
        ctx.api_url(api_id, _STAGE, websocket=False)
    ).hostname
    assert request_context.get("domainName") == expected_domain, (
        f"expected requestContext.domainName {expected_domain!r}, got "
        f"{request_context.get('domainName')!r}"
    )
    assert request_context.get("stage") == _STAGE, (
        f"expected requestContext.stage {_STAGE!r}, got {request_context.get('stage')!r}"
    )

    qs = event.get("queryStringParameters") or {}
    assert qs.get("marker") == marker, (
        f"expected queryStringParameters.marker {marker!r}, got {qs.get('marker')!r}"
    )

    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    assert headers.get("sec-websocket-key") == sent_keys[-1], (
        f"expected the upgraded handshake's Sec-WebSocket-Key {sent_keys[-1]!r} in the $connect "
        f"event's headers, got {headers.get('sec-websocket-key')!r}"
    )
    assert headers.get("sec-websocket-version") == "13", (
        f"expected Sec-WebSocket-Version '13' in the $connect event's headers, got "
        f"{headers.get('sec-websocket-version')!r}"
    )
    assert headers.get("sec-websocket-extensions") == query_extensions, (
        f"expected Sec-WebSocket-Extensions {query_extensions!r} passed through to the $connect "
        f"event's headers, got {headers.get('sec-websocket-extensions')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
