"""appsync-subscription-payload-format."""
from __future__ import annotations

import base64
import json
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import quote, urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-subscription-payload-format"
GROUP = "data-format"
SERVICES = ["appsync", "cognito-idp", "dynamodb"]

SCHEMA_SDL = """
schema {
  query: Query
  mutation: Mutation
  subscription: Subscription
}

type Post {
  id: ID!
  content: String!
  owner: String
}

type Query {
  getPost(id: ID!): Post
}

type Mutation {
  createPost(id: ID!, content: String!, owner: String): Post
}

type Subscription {
  onCreatePost(id: ID, owner: String): Post
    @aws_subscribe(mutations: ["createPost"])
}
"""

CREATE_POST_REQUEST_VTL = """{
    "version": "2018-05-29",
    "operation": "PutItem",
    "key": { "id": $util.dynamodb.toDynamoDBJson($ctx.args.id) },
    "attributeValues": {
        "content": $util.dynamodb.toDynamoDBJson($ctx.args.content),
        "owner": $util.dynamodb.toDynamoDBJson($util.defaultIfNull($ctx.args.owner, "unset"))
    }
}"""

# Under VTL mapping-template version 2018-05-29, a data source invocation error does NOT
# automatically become a GraphQL error -- $ctx.result is simply null and the developer must
# check $ctx.error explicitly, or a transient AccessDenied (IAM role/policy propagation lag on
# a just-created service role) is silently swallowed as a null response instead of failing loudly.
CREATE_POST_RESPONSE_VTL = """#if($ctx.error)
    $util.error($ctx.error.message, $ctx.error.type)
#end
$util.toJson($ctx.result)"""


CREATE_POST_MUTATION = """
mutation CreatePost($id: ID!, $content: String!, $owner: String) {
  createPost(id: $id, content: $content, owner: $owner) {
    id
    content
    owner
  }
}
"""

SUBSCRIBE_QUERY = """
subscription OnCreatePost {
  onCreatePost {
    id
    content
    owner
  }
}
"""


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:e2e", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The pushed subscription payload has the exact same shape/values as the mutation's own
    DynamoDB-derived response (same selection set -> byte-identical field values)."""
    stack = _provision_stack(ctx, SCHEMA_SDL)
    auth_header = {"x-api-key": stack["api_key"]}

    ws = _ws_connect(ctx, stack["realtime_url"], stack["host"], auth_header)
    ctx.on_cleanup(ws.close)
    sub_id = str(uuid.uuid4())
    ack = _ws_start(ws, stack["host"], auth_header, sub_id, SUBSCRIBE_QUERY)
    assert ack["type"] == "start_ack", f"subscription registration failed: {ack}"

    post_id = ctx.unique_name("post-")

    # First write through the freshly-created resolver: the service role's IAM policy may not
    # have propagated yet, so retry on AccessDenied-shaped GraphQL errors.
    def _first_mutation():
        return _graphql_http(
            ctx, stack["graphql_url"],
            auth_header,
            CREATE_POST_MUTATION,
            {"id": post_id, "content": "format-check-body", "owner": "format-owner"},
        )

    resp = _poll_until(
        _first_mutation,
        lambda r: "errors" not in r,
        timeout_s=60,
        interval_s=5,
        description="createPost mutation (IAM role propagation)",
    )
    assert "errors" not in resp, f"createPost mutation failed: {resp.get('errors')}"
    mutation_result = resp["data"]["createPost"]


    delivered = _ws_wait_data(ws, sub_id, timeout_s=30.0)
    _ws_stop(ws, sub_id)
    assert delivered is not None, "no subscription event delivered within 30s of the mutation"

    # The subscription "data" envelope must contain exactly the queried root field.
    assert list(delivered.keys()) == ["onCreatePost"], (
        f"expected the data envelope to contain exactly ['onCreatePost'], got {list(delivered.keys())!r}"
    )
    pushed_post = delivered["onCreatePost"]

    # Shape: same keys as the mutation's own selection set.
    assert set(pushed_post.keys()) == set(mutation_result.keys()) == {"id", "content", "owner"}, (
        f"expected both the pushed payload and the mutation response to have keys "
        f"{{'id', 'content', 'owner'}}, got pushed={sorted(pushed_post.keys())!r} "
        f"mutation={sorted(mutation_result.keys())!r}"
    )
    # Values: the push is derived from the same DynamoDB write the mutation resolver produced.
    assert pushed_post == mutation_result, (
        f"expected the pushed subscription payload to equal the mutation's own response, "
        f"got pushed={pushed_post!r} != mutation={mutation_result!r}"
    )
    assert isinstance(pushed_post["id"], str) and isinstance(pushed_post["content"], str), (
        f"expected string id/content in the pushed payload, got id={pushed_post['id']!r} "
        f"({type(pushed_post['id']).__name__}) content={pushed_post['content']!r} "
        f"({type(pushed_post['content']).__name__})"
    )


class _WSTimeout(Exception):
    """No complete frame arrived before the deadline."""


class _WSClient:
    """Minimal stdlib-only RFC6455 text-frame WebSocket client (socket+ssl+struct), so the
    check has no third-party WebSocket dependency.
    """

    def __init__(self, url: str, route_headers=None, *, subprotocol: str, timeout_s: float = 15.0):
        parts = urlparse(url)
        self.host = parts.hostname
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        self._buf = b""
        self._timeout_s = timeout_s
        secure = parts.scheme in ("wss", "https")
        raw = socket.create_connection((self.host, parts.port or (443 if secure else 80)), timeout=timeout_s)
        self._sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host) if secure else raw
        self._sock.settimeout(timeout_s)
        nonce = base64.b64encode(uuid.uuid4().bytes).decode()
        self._sock.sendall(
            (
                f"GET {target} HTTP/1.1\r\n"
                f"Host: {(route_headers or {}).get('Host') or self.host}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {nonce}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Sec-WebSocket-Protocol: {subprotocol}\r\n"
                "\r\n"
            ).encode()
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self._sock.recv(4096)
            if not chunk:
                break
            head += chunk
        header_bytes, _, rest = head.partition(b"\r\n\r\n")
        self._buf = rest
        status_line = header_bytes.split(b"\r\n", 1)[0].decode("latin-1")
        bits = status_line.split(" ")
        self.status = int(bits[1]) if len(bits) > 1 and bits[1].isdigit() else 0

    def settimeout(self, timeout_s: float) -> None:
        self._timeout_s = timeout_s

    def send(self, text: str) -> None:
        self._send_frame(0x1, text.encode())

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        n = len(payload)
        frame = bytearray([0x80 | opcode])
        if n < 126:
            frame.append(0x80 | n)
        elif n < 65536:
            frame.append(0x80 | 126)
            frame += struct.pack("!H", n)
        else:
            frame.append(0x80 | 127)
            frame += struct.pack("!Q", n)
        mask = uuid.uuid4().bytes[:4]
        frame += mask
        frame += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(bytes(frame))

    def _fill(self, deadline: float) -> bool:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        self._sock.settimeout(min(remaining, 2.0))
        try:
            chunk = self._sock.recv(8192)
        except (socket.timeout, TimeoutError):
            return time.monotonic() < deadline
        except OSError:
            return False
        if not chunk:
            return False
        self._buf += chunk
        return True

    def _need(self, n: int, deadline: float) -> bool:
        while len(self._buf) < n:
            if not self._fill(deadline):
                return False
        return True

    def _recv_frame(self, deadline: float):
        if not self._need(2, deadline):
            return None
        b0, b1 = self._buf[0], self._buf[1]
        ln, off = b1 & 0x7F, 2
        if ln == 126:
            if not self._need(4, deadline):
                return None
            ln, off = struct.unpack("!H", bytes(self._buf[2:4]))[0], 4
        elif ln == 127:
            if not self._need(10, deadline):
                return None
            ln, off = struct.unpack("!Q", bytes(self._buf[2:10]))[0], 10
        if not self._need(off + ln, deadline):
            return None
        payload = bytes(self._buf[off:off + ln])
        self._buf = self._buf[off + ln:]
        return b0 & 0x0F, payload

    def recv(self) -> str:
        """Next text message, blocking up to the last ``settimeout`` value. Pings are ponged
        and pongs are dropped transparently; a close frame surfaces as a synthetic message
        rather than a timeout, so a server-initiated close is observable, not silent."""
        deadline = time.monotonic() + self._timeout_s
        while True:
            frame = self._recv_frame(deadline)
            if frame is None:
                raise _WSTimeout(f"no websocket frame within {self._timeout_s}s")
            opcode, payload = frame
            if opcode == 0x9:  # ping
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode == 0x8:  # close
                return json.dumps({"type": "__closed__"})
            return payload.decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self._send_frame(0x8, b"\x03\xe8")
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _provision_stack(ctx, schema_sdl: str) -> dict:
    """Provision a DynamoDB-backed AppSync API (API_KEY auth) for a Post model."""
    region = ctx.region
    appsync = ctx.client("appsync")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")

    table_name = ctx.unique_name("sim2real-appsync-posts-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    role_name = ctx.unique_name("sim2real-appsync-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "appsync.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="ddb-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                        "Resource": [table_arn, f"{table_arn}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="ddb-access"))

    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    graphql_url = api["uris"]["GRAPHQL"]
    realtime_url = api["uris"].get("REALTIME") or graphql_url.replace(
        "https://", "wss://"
    ).replace("appsync-api", "appsync-realtime-api")
    host = urlparse(graphql_url).netloc

    api_key = appsync.create_api_key(apiId=api_id, expires=int(time.time()) + 90000)["apiKey"]["id"]

    appsync.start_schema_creation(apiId=api_id, definition=schema_sdl.encode())
    status = _poll_until(
        lambda: appsync.get_schema_creation_status(apiId=api_id)["status"],
        lambda s: s != "PROCESSING",
        timeout_s=60,
        interval_s=2,
        description="schema creation",
    )
    assert status == "SUCCESS", f"schema creation failed: {status}"

    def _create_ds():
        try:
            return appsync.create_data_source(
                apiId=api_id,
                name="PostsTable",
                type="AMAZON_DYNAMODB",
                dynamodbConfig={"tableName": table_name, "awsRegion": region},
                serviceRoleArn=role["Arn"],
            )
        except ClientError as exc:
            return exc

    ds_result = _poll_until(
        _create_ds,
        lambda r: not isinstance(r, ClientError),
        timeout_s=60,
        interval_s=5,
        description="data source creation (IAM role propagation)",
    )
    assert not isinstance(ds_result, ClientError), f"data source creation never succeeded: {ds_result}"

    appsync.create_resolver(
        apiId=api_id,
        typeName="Mutation",
        fieldName="createPost",
        dataSourceName="PostsTable",
        requestMappingTemplate=CREATE_POST_REQUEST_VTL,
        responseMappingTemplate=CREATE_POST_RESPONSE_VTL,
    )

    return {
        "region": region,
        "graphql_url": graphql_url,
        "realtime_url": realtime_url,
        "host": host,
        "table_name": table_name,
        "api_key": api_key,
    }


def _ws_connect(ctx, realtime_url: str, host: str, auth_header: dict):
    header = {"host": host, **auth_header}
    header_b64 = base64.b64encode(json.dumps(header).encode()).decode()
    payload_b64 = base64.b64encode(b"{}").decode()
    url = f"{realtime_url}?header={quote(header_b64, safe='')}&payload={quote(payload_b64, safe='')}"
    ws = _WSClient(*ctx.endpoint_route(url, websocket=True), subprotocol="graphql-ws", timeout_s=15)
    assert ws.status == 101, f"the realtime endpoint refused the WebSocket upgrade: HTTP {ws.status}"
    ws.send(json.dumps({"type": "connection_init"}))
    ws.settimeout(15)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            msg = json.loads(ws.recv())
        except _WSTimeout:
            continue
        if msg.get("type") == "connection_ack":
            return ws
        if msg.get("type") == "error":
            ws.close()
            raise AssertionError(f"connection_init failed: {msg}")
    ws.close()
    raise AssertionError("no connection_ack received within 15s")


def _ws_start(ws, host: str, auth_header: dict, sub_id: str, query: str, variables: dict | None = None):
    payload = {
        "data": json.dumps({"query": query, "variables": variables or {}}),
        "extensions": {"authorization": {"host": host, **auth_header}},
    }
    ws.send(json.dumps({"id": sub_id, "type": "start", "payload": payload}))
    ws.settimeout(15)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            msg = json.loads(ws.recv())
        except _WSTimeout:
            continue
        if msg.get("id") != sub_id:
            continue
        if msg.get("type") in ("start_ack", "error"):
            return msg
    raise AssertionError("no start_ack/error received within 15s")


def _ws_wait_data(ws, sub_id: str, timeout_s: float = 30.0):
    ws.settimeout(2.0)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            raw = ws.recv()
        except _WSTimeout:
            continue
        if not raw:
            continue
        msg = json.loads(raw)
        if msg.get("id") != sub_id:
            continue
        if msg.get("type") == "data":
            return msg["payload"]["data"]
        if msg.get("type") == "error":
            raise AssertionError(f"subscription error: {msg['payload']}")
    return None


def _ws_stop(ws, sub_id: str) -> None:
    try:
        ws.send(json.dumps({"id": sub_id, "type": "stop"}))
    except Exception:
        pass


def _graphql_http(ctx, url: str, headers: dict, query: str, variables: dict | None = None) -> dict:
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=body, method="POST", headers={"Content-Type": "application/json", **headers, **route_headers}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read().decode())


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
