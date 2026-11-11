"""appsync-subscription-cognito-group-filter-positive."""
from __future__ import annotations

import base64
import json
import os
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

CHECK = "appsync-subscription-cognito-group-filter-positive"
GROUP = "event-propagation"
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
  onCreatePostForEditors(id: ID): Post
    @aws_subscribe(mutations: ["createPost"])
    @aws_auth(cognito_groups: ["Editors"])
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

SUBSCRIBE_EDITORS_QUERY = """
subscription OnCreatePostForEditors {
  onCreatePostForEditors {
    id
    content
  }
}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c6", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Cognito user whose ID token carries the "Editors" group claim can subscribe to a field
    restricted with @aws_auth(cognito_groups: ["Editors"]) and receives the mutation-triggered
    push."""
    stack = _provision_stack(ctx, SCHEMA_SDL)
    id_token = _create_cognito_user(
        ctx, stack["pool_id"], stack["client_id"], ctx.unique_name("editor-"), groups=["Editors"]
    )
    auth_header = {"Authorization": id_token}

    ws = _ws_connect(ctx, stack["realtime_url"], stack["host"], auth_header)
    ctx.on_cleanup(ws.close)
    sub_id = str(uuid.uuid4())
    ack = _ws_start(ws, stack["host"], auth_header, sub_id, SUBSCRIBE_EDITORS_QUERY)
    assert ack["type"] == "start_ack", f"in-group subscriber was rejected: {ack}"

    post_id = ctx.unique_name("post-")

    # First write through the freshly-created resolver: the service role's IAM policy may not
    # have propagated yet, so retry on AccessDenied-shaped GraphQL errors.
    def _first_mutation():
        return _graphql_http(
            ctx, stack["graphql_url"],
            auth_header,
            CREATE_POST_MUTATION,
            {"id": post_id, "content": "editors-only-content", "owner": "editor"},
        )

    resp = _poll_until(
        _first_mutation,
        lambda r: "errors" not in r,
        timeout_s=60,
        interval_s=5,
        description="createPost mutation (IAM role propagation)",
    )
    assert "errors" not in resp, f"createPost mutation failed: {resp.get('errors')}"


    delivered = _ws_wait_data(ws, sub_id, timeout_s=30.0)
    _ws_stop(ws, sub_id)
    assert delivered is not None, "in-group subscriber never received the mutation push"
    event = delivered["onCreatePostForEditors"]
    assert event["id"] == post_id, f"pushed event id {event['id']!r} != created post id {post_id!r}"
    assert event["content"] == "editors-only-content", f"pushed event content was {event['content']!r}"

    item = ctx.client("dynamodb").get_item(
        TableName=stack["table_name"], Key={"id": {"S": post_id}}
    )["Item"]
    assert item["content"]["S"] == "editors-only-content", (
        f"resolver did not persist the mutation to DynamoDB: {item}"
    )


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
    """Provision a DynamoDB-backed AppSync API (Cognito user pool auth) for a Post model."""
    region = ctx.region
    appsync = ctx.client("appsync")
    ddb = ctx.client("dynamodb")
    iam = ctx.client("iam")
    cognito = ctx.client("cognito-idp")

    table_name = ctx.unique_name("sim2real-appsync-posts-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
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
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
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

    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-appsync-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-appsync-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    client_id = client["ClientId"]

    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-api-"),
        authenticationType="AMAZON_COGNITO_USER_POOLS",
        userPoolConfig={"userPoolId": pool_id, "awsRegion": region, "defaultAction": "ALLOW"},
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    graphql_url = api["uris"]["GRAPHQL"]
    realtime_url = api["uris"].get("REALTIME") or graphql_url.replace(
        "https://", "wss://"
    ).replace("appsync-api", "appsync-realtime-api")
    host = urlparse(graphql_url).netloc

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
        "pool_id": pool_id,
        "client_id": client_id,
    }


def _create_cognito_user(
    ctx, pool_id: str, client_id: str, username: str, groups: list[str] | None = None,
    password: str = "Sim2Real-Pass1!",
) -> str:
    cognito = ctx.client("cognito-idp")
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    for group in groups or []:
        try:
            cognito.create_group(GroupName=group, UserPoolId=pool_id)
            ctx.on_cleanup(lambda g=group: cognito.delete_group(GroupName=g, UserPoolId=pool_id))
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "GroupExistsException":
                raise
        cognito.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group)
    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]


class _RealtimeSocket:
    """Minimal RFC6455 text-frame client over TLS, stdlib only.

    ``websocket-client`` is not installed on the runner host (measured: `import websocket` raises
    ``ModuleNotFoundError``), so the handshake is inlined rather than depending on a package that is
    not actually there.
    """

    def __init__(self, url: str, route_headers=None, *, subprotocol: str = "graphql-ws", timeout_s: float = 15.0):
        parts = urlparse(url)
        self.host = parts.hostname
        target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
        self.eof = False
        self._buf = b""
        secure = parts.scheme in ("wss", "https")
        raw = socket.create_connection((self.host, parts.port or (443 if secure else 80)), timeout=timeout_s)
        self._sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host) if secure else raw
        nonce = base64.b64encode(os.urandom(16)).decode()
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
        self._sock.settimeout(timeout_s)
        while b"\r\n\r\n" not in head:
            try:
                chunk = self._sock.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            head += chunk
        raw_head, _, rest = head.partition(b"\r\n\r\n")
        self._buf = rest
        line = raw_head.split(b"\r\n", 1)[0].decode("latin-1")
        bits = line.split(" ")
        self.status = int(bits[1]) if len(bits) > 1 and bits[1].isdigit() else 0
        self.headers = raw_head.decode("latin-1")

    def _fill(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        self._sock.settimeout(min(remaining, 5.0))
        try:
            chunk = self._sock.recv(8192)
        except (socket.timeout, TimeoutError):
            return time.monotonic() < deadline
        except OSError:
            self.eof = True
            return False
        if not chunk:
            self.eof = True
            return False
        self._buf += chunk
        return True

    def _need(self, n, deadline):
        while len(self._buf) < n:
            if not self._fill(deadline):
                return False
        return True

    def _send_frame(self, opcode, payload):
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
        mask = os.urandom(4)
        frame += mask
        frame += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(bytes(frame))

    def send_json(self, obj):
        self._send_frame(0x1, json.dumps(obj).encode())

    def _recv_frame(self, deadline):
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
        return (b0 & 0x0F, payload, bool(b0 & 0x80))

    def recv_json(self, deadline):
        """Next application message as a dict, or None once ``deadline`` passes.

        A ping is ponged rather than surfaced, and a close frame becomes a synthetic
        ``__closed__`` message so a refusal is observable instead of looking like a timeout.
        """
        parts = []
        while True:
            frame = self._recv_frame(deadline)
            if frame is None:
                return None
            opcode, payload, fin = frame
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x8:
                self.eof = True
                return {"type": "__closed__"}
            parts.append(payload)
            if not fin:
                continue
            text = b"".join(parts).decode("utf-8", "replace")
            parts = []
            try:
                return json.loads(text)
            except ValueError:
                return {"type": "__unparsed__", "raw": text}

    def close(self):
        try:
            self._send_frame(0x8, b"\x03\xe8")
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


def _ws_connect(ctx, realtime_url: str, host: str, auth_header: dict):
    header = {"host": host, **auth_header}
    header_b64 = base64.b64encode(json.dumps(header).encode()).decode()
    payload_b64 = base64.b64encode(b"{}").decode()
    url = f"{realtime_url}?header={quote(header_b64, safe='')}&payload={quote(payload_b64, safe='')}"
    ws = _RealtimeSocket(*ctx.endpoint_route(url, websocket=True))
    if ws.status != 101:
        ws.close()
        raise AssertionError(
            f"the realtime endpoint refused the WebSocket upgrade: HTTP {ws.status!r} "
            f"headers={ws.headers[:400]!r}"
        )
    deadline = time.monotonic() + 15
    ws.send_json({"type": "connection_init"})
    while time.monotonic() < deadline:
        msg = ws.recv_json(deadline)
        if msg is None:
            break
        if msg.get("type") == "connection_ack":
            return ws
        if msg.get("type") in ("error", "__closed__"):
            ws.close()
            raise AssertionError(f"connection_init failed: {msg}")
    ws.close()
    raise AssertionError("no connection_ack received within 15s")


def _ws_start(ws, host: str, auth_header: dict, sub_id: str, query: str, variables: dict | None = None):
    payload = {
        "data": json.dumps({"query": query, "variables": variables or {}}),
        "extensions": {"authorization": {"host": host, **auth_header}},
    }
    ws.send_json({"id": sub_id, "type": "start", "payload": payload})
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        msg = ws.recv_json(deadline)
        if msg is None:
            break
        if msg.get("id") != sub_id:
            continue
        if msg.get("type") in ("start_ack", "error"):
            return msg
    raise AssertionError("no start_ack/error received within 15s")


def _ws_wait_data(ws, sub_id: str, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msg = ws.recv_json(deadline)
        if msg is None:
            continue
        if msg.get("id") != sub_id:
            continue
        if msg.get("type") == "data":
            return msg["payload"]["data"]
        if msg.get("type") == "error":
            raise AssertionError(f"subscription error: {msg['payload']}")
    return None


def _ws_stop(ws, sub_id: str) -> None:
    try:
        ws.send_json({"id": sub_id, "type": "stop"})
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
