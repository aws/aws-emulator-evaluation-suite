"""appsync-iam-signed-mutation-reaches-realtime-subscriber-and-query-reads-it-back."""
from __future__ import annotations

import base64
import json
import ssl
import time
import uuid
from urllib.parse import quote, urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-iam-signed-mutation-reaches-realtime-subscriber-and-query-reads-it-back"
GROUP = "data-plane"
SERVICES = ["appsync", "dynamodb"]

_TAGS = {"sim2real": CHECK, "sim2real:managed": "true"}

SDL = """schema { query: Query mutation: Mutation subscription: Subscription }
type Note {
    id: ID!
    board: String!
    body: String!
    author: String
}
type Query {
    getNote(id: ID!): Note
}
type Mutation {
    createNote(id: ID!, board: String!, body: String!): Note
}
type Subscription {
    onCreateNote(board: String): Note @aws_subscribe(mutations: ["createNote"])
}
"""

#: The resolver stores the signer's account from ``ctx.identity``, which only an IAM-authorized
#: request carries, so the stored and the pushed ``author`` both prove the signature was evaluated.
JS_CREATE = """import { util } from '@aws-appsync/utils';
import * as ddb from '@aws-appsync/utils/dynamodb';

export function request(ctx) {
  const { id, board, body } = ctx.args;
  return ddb.put({ key: { id }, item: { board, body, author: ctx.identity.accountId } });
}

export function response(ctx) {
  if (ctx.error) {
    util.error(ctx.error.message, ctx.error.type);
  }
  return ctx.result;
}
"""

JS_GET = """import { util } from '@aws-appsync/utils';
import * as ddb from '@aws-appsync/utils/dynamodb';

export function request(ctx) {
  return ddb.get({ key: { id: ctx.args.id }, consistentRead: true });
}

export function response(ctx) {
  if (ctx.error) {
    util.error(ctx.error.message, ctx.error.type);
  }
  return ctx.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}

CREATE = (
    "mutation CreateNote($id: ID!, $board: String!, $body: String!) "
    "{ createNote(id: $id, board: $board, body: $body) { id board body author } }"
)
GET = "query GetNote($id: ID!) { getNote(id: $id) { id board body author } }"
SUBSCRIBE = (
    "subscription OnCreateNote($board: String) "
    "{ onCreateNote(board: $board) { id board body author } }"
)

#: The headers AppSync's real-time protocol signs for IAM: the connect and every start message.
_REALTIME_HEADERS = {
    "accept": "application/json, text/javascript",
    "content-encoding": "amz-1.0",
    "content-type": "application/json; charset=UTF-8",
}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=120.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) holds; return that result or raise on timeout."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _teardown(undo, *not_found):
    """A cleanup running ``undo()`` where a failed delete raises, unless the resource is gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _try(fn, **kwargs):
    """The call's result, or the AWS error code it raised."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _create_table(ctx):
    """An on-demand table keyed by the string ``id``, ACTIVE, teardown registered."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-appsync-notes-")
    arn = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    _poll_until(
        ctx,
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        description=f"table {name} ACTIVE",
    )
    return name, arn


def _delete_role(iam, role_name):
    for policy in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy)
    iam.delete_role(RoleName=role_name)


def _service_role(ctx, table_arn):
    """A role AppSync assumes to read and write only this table, teardown registered."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-role-")
    arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "appsync.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: _delete_role(iam, role_name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                           "Resource": table_arn}],
        }),
    )
    return arn


def _iam_api(ctx, table, role_arn):
    """An AWS_IAM GraphQL API with JS resolvers over the table; returns its GRAPHQL and REALTIME URIs."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-iam-"),
        authenticationType="AWS_IAM",
        tags=_TAGS,
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(_teardown(lambda: svc.delete_graphql_api(apiId=api_id), "NotFoundException"))
    svc.start_schema_creation(apiId=api_id, definition=SDL.encode())
    status = _poll_until(
        ctx,
        lambda: svc.get_schema_creation_status(apiId=api_id)["status"],
        lambda s: s in ("SUCCESS", "ACTIVE", "FAILED"),
        description="schema creation to finish",
    )
    assert status in ("SUCCESS", "ACTIVE"), f"schema creation ended {status!r}, expected SUCCESS"
    _poll_until(
        ctx,
        lambda: _try(svc.create_data_source, apiId=api_id, name="Notes", type="AMAZON_DYNAMODB",
                     serviceRoleArn=role_arn,
                     dynamodbConfig={"tableName": table, "awsRegion": ctx.region}),
        lambda outcome: isinstance(outcome, dict),
        interval_s=5.0,
        description="CreateDataSource to accept the new service role",
    )
    for type_name, field, code in (("Mutation", "createNote", JS_CREATE), ("Query", "getNote", JS_GET)):
        svc.create_resolver(apiId=api_id, typeName=type_name, fieldName=field, kind="UNIT",
                            dataSourceName="Notes", runtime=APPSYNC_JS, code=code)
    uris = api.get("uris") or {}
    assert uris.get("GRAPHQL") and uris.get("REALTIME"), (
        f"CreateGraphqlApi published no GRAPHQL and REALTIME endpoints: {uris!r}"
    )
    return uris["GRAPHQL"], uris["REALTIME"]


def _signer(ctx):
    """An AWS4Auth for the ``appsync`` signing name over the keys ``ctx.client`` signs with."""
    from requests_aws4auth import AWS4Auth

    creds = ctx.client("appsync")._request_signer._credentials.get_frozen_credentials()
    return AWS4Auth(
        creds.access_key, creds.secret_key, ctx.region, "appsync",
        session_token=creds.token,
        include_hdrs={"accept", "content-encoding", "content-type", "host", "x-amz-*"},
    )


def _signed_realtime_auth(ctx, graphql_url, path, body):
    """The signed header map AppSync's real-time protocol expects for a POST of ``body`` to ``path``."""
    import requests

    parts = urlsplit(graphql_url)
    prepared = requests.Request(
        "POST", parts._replace(path=path, query="").geturl(), data=body,
        headers={**_REALTIME_HEADERS, "host": parts.netloc},
    ).prepare()
    _signer(ctx)(prepared)
    return {k: v for k, v in prepared.headers.items() if k.lower() != "content-length"}


def _graphql(ctx, graphql_url, query, variables):
    """POST a SigV4-signed GraphQL request; return (HTTP status, parsed body)."""
    import requests

    url, route_headers = ctx.endpoint_route(graphql_url)
    resp = requests.post(
        url,
        data=json.dumps({"query": query, "variables": variables}),
        headers={"content-type": "application/json", **route_headers},
        auth=_signer(ctx),
        verify=ctx.http_verify,
        timeout=30,
    )
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, {"raw": resp.text[:300]}


def _sslopt(ctx):
    verify = ctx.http_verify
    if verify is False:
        return {"cert_reqs": ssl.CERT_NONE}
    return {"ca_certs": verify} if isinstance(verify, str) else {}


def _recv(ws, deadline, description):
    """The next JSON message, or None once ``deadline`` passes; keep-alives are skipped."""
    import websocket

    while time.monotonic() < deadline:
        ws.settimeout(max(0.5, deadline - time.monotonic()))
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            return None
        except websocket.WebSocketConnectionClosedException:
            raw = ""
        assert raw, f"{description}: the server closed the socket"
        msg = json.loads(raw)
        if msg.get("type") != "ka":
            return msg
    return None


def _await(ctx, ws, want, *, sub_id=None, timeout_s=30.0, description="message"):
    """The first message of type ``want`` (for ``sub_id`` when given); an ``error`` fails."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    seen = []
    while True:
        msg = _recv(ws, deadline, description)
        if msg is None:
            break
        if sub_id is not None and msg.get("id") not in (None, sub_id):
            continue
        if msg.get("type") == want:
            return msg
        seen.append(msg)
        assert msg.get("type") not in ("error", "connection_error", "start_error"), (
            f"{description}: expected {want!r}, got {msg!r}"
        )
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description}: no {want!r} within {timeout_s:.0f}s; other messages {seen!r}")


def _connect_realtime(ctx, graphql_url, realtime_url):
    """A WebSocket on the real-time endpoint authorized by a SigV4-signed connect header."""
    import websocket

    header = _signed_realtime_auth(ctx, graphql_url, "/graphql/connect", "{}")
    query = (
        f"header={quote(base64.b64encode(json.dumps(header).encode()).decode(), safe='')}"
        f"&payload={quote(base64.b64encode(b'{}').decode(), safe='')}"
    )
    url, route_headers = ctx.endpoint_route(f"{realtime_url}?{query}", websocket=True)
    try:
        ws = websocket.create_connection(
            url, subprotocols=["graphql-ws"], host=route_headers.get("Host"),
            sslopt=_sslopt(ctx), timeout=20,
        )
    except websocket.WebSocketBadStatusException as exc:
        raise AssertionError(
            f"the real-time endpoint refused the IAM-signed upgrade: HTTP {exc.status_code}, "
            f"expected 101"
        ) from exc
    ctx.on_cleanup(ws.close)
    ws.send(json.dumps({"type": "connection_init"}))
    return ws


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:e2e", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """On an AWS_IAM GraphQL API, a SigV4-signed subscriber receives the signed createNote event with
    the signer's account as author, the signed getNote query reads the same note back from the table,
    and an unknown id resolves to null.
    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/real-time-websocket-client.html
    """
    table, table_arn = _create_table(ctx)
    role_arn = _service_role(ctx, table_arn)
    graphql_url, realtime_url = _iam_api(ctx, table, role_arn)

    ws = _connect_realtime(ctx, graphql_url, realtime_url)
    ack = _await(ctx, ws, "connection_ack", description="connection_init on the IAM-signed socket")
    assert isinstance((ack.get("payload") or {}).get("connectionTimeoutMs"), int), (
        f"connection_ack carried no integer connectionTimeoutMs: {ack!r}"
    )

    board = ctx.unique_name("board-")
    sub_id = str(uuid.uuid4())
    data = json.dumps({"query": SUBSCRIBE, "variables": {"board": board}})
    ws.send(json.dumps({
        "id": sub_id,
        "type": "start",
        "payload": {
            "data": data,
            "extensions": {"authorization": _signed_realtime_auth(ctx, graphql_url, "/graphql", data)},
        },
    }))
    _await(ctx, ws, "start_ack", sub_id=sub_id, description="the IAM-signed subscription start")

    note_id = ctx.unique_name("note-")
    body = f"hello {uuid.uuid4().hex}"
    expected = {"id": note_id, "board": board, "body": body, "author": ctx.account}
    # The first write through a new service role retries until IAM propagation lets it resolve.
    status, created = _poll_until(
        ctx,
        lambda: _graphql(ctx, graphql_url, CREATE, {"id": note_id, "board": board, "body": body}),
        lambda r: r[0] == 200 and not r[1].get("errors"),
        interval_s=5.0,
        description="the signed createNote mutation to resolve",
    )
    returned = (created.get("data") or {}).get("createNote")
    assert returned == expected, f"createNote returned {returned!r}, expected {expected!r}"

    event = _await(ctx, ws, "data", sub_id=sub_id, description="the onCreateNote event")
    pushed = ((event.get("payload") or {}).get("data") or {}).get("onCreateNote")
    assert pushed == expected, f"the subscriber received {pushed!r}, expected {expected!r}"

    status, got = _graphql(ctx, graphql_url, GET, {"id": note_id})
    assert status == 200 and not got.get("errors"), f"getNote failed: HTTP {status} {got!r}"
    read = (got.get("data") or {}).get("getNote")
    assert read == expected, f"getNote returned {read!r}, expected {expected!r}"

    status, missing = _graphql(ctx, graphql_url, GET, {"id": ctx.unique_name("absent-")})
    assert status == 200 and not missing.get("errors"), f"getNote of an unknown id failed: {missing!r}"
    assert missing.get("data") == {"getNote": None}, (
        f"getNote of an unknown id returned {missing.get('data')!r}, expected {{'getNote': None}}"
    )

    item = ctx.client("dynamodb").get_item(
        TableName=table, Key={"id": {"S": note_id}}, ConsistentRead=True
    ).get("Item")
    stored = {k: v.get("S") for k, v in (item or {}).items()}
    assert stored == expected, f"the table holds {stored!r} for the note, expected {expected!r}"

    ws.send(json.dumps({"id": sub_id, "type": "stop"}))
    _await(ctx, ws, "complete", sub_id=sub_id, description="stop of the subscription")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
