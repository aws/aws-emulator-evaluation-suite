"""appsync-subscription-missing-subscribe-permission-negative."""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import quote, urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

try:
    import websocket  # websocket-client
except ImportError:  # pragma: no cover
    websocket = None

CHECK = "appsync-subscription-missing-subscribe-permission-negative"
GROUP = "overly-permissive"
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


@tags("axis:negative-delivery", "cap:c3", "cap:c6", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A user outside the "Editors" group cannot subscribe to an @aws_auth(cognito_groups: ["Editors"])
    field and gets no push while an in-group subscriber does; after joining the group and
    re-authenticating, the same subscription succeeds and delivers."""
    stack = _provision_stack(ctx, SCHEMA_SDL)
    outsider_username = ctx.unique_name("outsider-")
    outsider_token = _create_cognito_user(ctx, stack["pool_id"], stack["client_id"], outsider_username)
    editor_token = _create_cognito_user(
        ctx, stack["pool_id"], stack["client_id"], ctx.unique_name("editor-"), groups=["Editors"]
    )
    outsider_header = {"Authorization": outsider_token}
    editor_header = {"Authorization": editor_token}

    outsider_ws = _ws_connect(ctx, stack["realtime_url"], stack["host"], outsider_header)
    ctx.on_cleanup(outsider_ws.close)
    outsider_sub_id = str(uuid.uuid4())
    outsider_ack = _ws_start(
        outsider_ws, stack["host"], outsider_header, outsider_sub_id, SUBSCRIBE_EDITORS_QUERY
    )
    assert outsider_ack["type"] == "error", (
        f"a subscriber without the required Cognito group was registered instead of rejected: {outsider_ack}"
    )

    editor_ws = _ws_connect(ctx, stack["realtime_url"], stack["host"], editor_header)
    ctx.on_cleanup(editor_ws.close)
    editor_sub_id = str(uuid.uuid4())
    editor_ack = _ws_start(
        editor_ws, stack["host"], editor_header, editor_sub_id, SUBSCRIBE_EDITORS_QUERY
    )
    assert editor_ack["type"] == "start_ack", f"positive-control (in-group) subscriber was rejected: {editor_ack}"

    post_id = ctx.unique_name("post-")

    # First write through the freshly-created resolver: the service role's IAM policy may not
    # have propagated yet, so retry on AccessDenied-shaped GraphQL errors.
    def _first_mutation():
        return _graphql_http(
            ctx, stack["graphql_url"],
            editor_header,
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

    # Positive control: the in-group subscriber still receives the push.
    delivered = _ws_wait_data(editor_ws, editor_sub_id, timeout_s=30.0)
    _ws_stop(editor_ws, editor_sub_id)
    assert delivered is not None, "in-group positive-control subscriber never received the push"
    assert delivered["onCreatePostForEditors"]["id"] == post_id, (
        f"delivered post id {delivered['onCreatePostForEditors']['id']!r} != expected {post_id!r}"
    )

    # Effect absent: the outsider's (never-registered) subscription gets nothing, ever.
    absent = _ws_wait_data(outsider_ws, outsider_sub_id, timeout_s=15.0)
    assert absent is None, f"an unauthorized subscriber received a push despite being rejected: {absent}"

    # Restore: grant the outsider the Editors group and re-authenticate. AppSync's
    # @aws_auth(cognito_groups:...) directive reads the "cognito:groups" claim baked into the
    # ID token at issuance, not live group membership, so a fresh token is required -- the same
    # identity that was just rejected must now be let in by the identical subscription call.
    cognito = ctx.client("cognito-idp")
    cognito.admin_add_user_to_group(
        UserPoolId=stack["pool_id"], Username=outsider_username, GroupName="Editors"
    )
    restored_token = _authenticate(ctx, stack["pool_id"], stack["client_id"], outsider_username)
    restored_header = {"Authorization": restored_token}
    restored_ws = _ws_connect(ctx, stack["realtime_url"], stack["host"], restored_header)
    ctx.on_cleanup(restored_ws.close)
    restored_sub_id = str(uuid.uuid4())
    restored_ack = _ws_start(
        restored_ws, stack["host"], restored_header, restored_sub_id, SUBSCRIBE_EDITORS_QUERY
    )
    assert restored_ack["type"] == "start_ack", (
        f"the same outsider, now granted the Editors group, was still rejected: {restored_ack}"
    )

    restored_post_id = ctx.unique_name("post-restored-")
    resp = _graphql_http(
        ctx, stack["graphql_url"],
        editor_header,
        CREATE_POST_MUTATION,
        {"id": restored_post_id, "content": "restored-content", "owner": "editor"},
    )
    assert "errors" not in resp, f"createPost mutation failed after restore: {resp}"

    restored_delivered = _ws_wait_data(restored_ws, restored_sub_id, timeout_s=30.0)
    _ws_stop(restored_ws, restored_sub_id)
    assert restored_delivered is not None, (
        "the restored (now in-group) former outsider never received the push"
    )
    assert restored_delivered["onCreatePostForEditors"]["id"] == restored_post_id, (
        f"delivered post id {restored_delivered['onCreatePostForEditors']['id']!r} "
        f"!= expected {restored_post_id!r}"
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
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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
        tags={"sim2real": CHECK},
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
    return _authenticate(ctx, pool_id, client_id, username, password)


def _authenticate(
    ctx, pool_id: str, client_id: str, username: str, password: str = "Sim2Real-Pass1!"
) -> str:
    """Mint a fresh ID token for an existing user -- used both at user creation and to pick up a
    group membership granted after the user's original token was already issued."""
    cognito = ctx.client("cognito-idp")
    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]


def _ws_connect(ctx, realtime_url: str, host: str, auth_header: dict):
    if websocket is None:
        from fidelity_tests_runner import RequiredToolMissing

        # websocket-client opens the AppSync real-time (wss://) connection; a runner without it is tool_missing.
        raise RequiredToolMissing(["websocket"], "module")
    header = {"host": host, **auth_header}
    header_b64 = base64.b64encode(json.dumps(header).encode()).decode()
    payload_b64 = base64.b64encode(b"{}").decode()
    url = f"{realtime_url}?header={quote(header_b64, safe='')}&payload={quote(payload_b64, safe='')}"
    routed_url, route_headers = ctx.endpoint_route(url, websocket=True)
    ws = websocket.create_connection(routed_url, subprotocols=["graphql-ws"], timeout=15, host=route_headers.get("Host"))
    ws.send(json.dumps({"type": "connection_init"}))
    ws.settimeout(15)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            msg = json.loads(ws.recv())
        except websocket.WebSocketTimeoutException:
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
        except websocket.WebSocketTimeoutException:
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
        except websocket.WebSocketTimeoutException:
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
