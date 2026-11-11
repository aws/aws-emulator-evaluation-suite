"""appsync-batch-get-item-resolver-preserves-arity-and-appends-per-key-errors."""
from __future__ import annotations

# Two AppSync JS engine quirks, undocumented by AWS:
#   Q1  the JS resolver's ``BatchGetItem`` per-table value must be ``{ keys: [...] }`` -- an OBJECT,
#       with no ``consistentRead`` field. AWS's own reference docs disagree with themselves: the
#       page's TypeScript type declaration shows the object form (with an optional
#       ``consistentRead``), but the page's own worked *code example* uses a bare array of keys.
#       Neither is quite right: the bare-array form is accepted by CreateResolver but rejected at
#       INVOKE time (``Expected JSON object for '$[tables][<table>]' but got a 'ARRAY' instead``),
#       and adding ``consistentRead`` to the object form makes CreateResolver itself reject the code
#       with the unhelpful ``The code contains one or more errors``. Only the bare
#       ``{ keys: [...] }`` object -- no ``consistentRead``, no ``projection`` -- compiles AND runs.
#   Q2  ``util.appendError`` cannot be called from inside a ``for`` statement -- CreateResolver
#       rejects it with the same unhelpful ``The code contains one or more errors``, even with zero
#       other changes. Calling it from inside ``Array.prototype.forEach`` compiles and runs fine.
#       This check uses ``items.forEach(...)`` for exactly that reason; do not "simplify" it back to
#       a ``for`` loop.
# The contract on AWS:
#   H1  a DynamoDB ``BatchGetItem`` resolver returns ``ctx.result.data[<table>]`` as a list of the
#       SAME LENGTH and SAME ORDER as the requested keys, with ``null`` at each position whose key
#       was not found -- not a compacted list of found items, and not a whole-request error.
#   H2  ``ctx.result.unprocessedKeys[<table>]`` is an EMPTY list when the request was fully served
#       (an on-demand table well inside its capacity).
#   H3  ``util.appendError(message, errorType, data, errorInfo)`` yields one GraphQL ``errors``
#       entry per call, carrying ``errorType`` and ``errorInfo`` verbatim, alongside a partial
#       ``data`` (200, not 4xx).
#   H4  ``errors[].path`` for an appendError raised in a LIST field's response handler is
#       ``["<fieldName>"]`` -- the field itself, with NO index into the list. Asserted below.
#   H5  the resolver's DynamoDB role needs dynamodb:BatchGetItem (and the check's own independent
#       read uses the caller's own credentials, not the resolver's role).

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-batch-get-item-resolver-preserves-arity-and-appends-per-key-errors"
GROUP = "server-side"
SERVICES = ["appsync", "dynamodb"]

PRESENT_INDICES = (0, 2, 4)
ABSENT_INDICES = (1, 3)
FANOUT = 5
MISSING_ERROR_TYPE = "SimParityMissingKey"
UNPROCESSED_ERROR_TYPE = "SimParityUnprocessed"

SDL = """schema { query: Query }
type Item {
    id: ID!
    value: String
}
type Query {
    batchLookup(ids: [ID!]!): [Item]
}
"""

# TABLE_NAME is substituted with the table this check created. The response handler turns each
# null hole into exactly one appended error naming the key that produced it, and separately
# reports any unprocessedKeys -- so both the arity contract and the throttle contract become
# observable in the GraphQL envelope.
JS_BATCH_GET = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'BatchGetItem',
    tables: {
      'TABLE_NAME': {
        keys: ctx.args.ids.map((id) => util.dynamodb.toMapValues({ id })),
      },
    },
  };
}

export function response(ctx) {
  if (ctx.error) {
    util.error(ctx.error.message, ctx.error.type);
  }
  const items = ctx.result.data['TABLE_NAME'];
  const unprocessed = (ctx.result.unprocessedKeys || {})['TABLE_NAME'] || [];
  items.forEach((item, i) => {
    if (item === null) {
      util.appendError(
        'missing:' + ctx.args.ids[i],
        'MISSING_ERROR_TYPE',
        null,
        { index: i, requestedId: ctx.args.ids[i] }
      );
    }
  });
  if (unprocessed.length > 0) {
    util.appendError('unprocessed:' + unprocessed.length, 'UNPROCESSED_ERROR_TYPE');
  }
  return items;
}
"""


def _resolver_code(table_name):
    return (
        JS_BATCH_GET
        .replace("TABLE_NAME", table_name)
        .replace("MISSING_ERROR_TYPE", MISSING_ERROR_TYPE)
        .replace("UNPROCESSED_ERROR_TYPE", UNPROCESSED_ERROR_TYPE)
    )


APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


# ===== helpers =====


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _alnum(ctx, prefix):
    """AppSync DataSource names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens allowed."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=40):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _try(fn, **kwargs):
    """The call's result, or the AWS error code -- never a bare False, so a poll timeout names
    the code that kept it from settling."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchEntity",):
            raise RuntimeError(
                f"role {role_name} not deleted: {exc.response.get('Error', {}).get('Code')}"
            ) from exc


def _create_role(ctx, trust_service, inline_policy):
    """An IAM role trusted by ``trust_service``, with its teardown registered.

    The short sleep is the ONE sanctioned bare wait: IAM exposes no condition reporting that a
    trust policy has become effective. The bounded retry at FIRST USE is what makes the check
    correct; the sleep only makes it cheaper.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-batchget-role-")
    arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return arn


def _create_table(ctx):
    """An on-demand table with one STRING hash key. Keys are ALWAYS typed."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-appsync-batchget-")
    arn = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_tags_kv(),
    )["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _poll_until(
        lambda: ddb.describe_table(TableName=name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0, interval_s=3.0,
        description=f"DynamoDB table {name} reaching ACTIVE",
    )
    return name, arn


def _graphql_api(ctx, svc, sdl):
    """Create an API_KEY GraphQL API + an ACTIVE schema + a key -> (api_id, uri, key)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: svc.delete_graphql_api(apiId=api_id))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=180.0, interval_s=2.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), (
        f"schema creation did not succeed: expected SUCCESS/ACTIVE, got {status['status']!r} "
        f"details={status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav batchget key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))
    return api_id, uri, key


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A BatchGetItem resolver over five keys (three seeded) returns a list of the same length and
    order with null at each missing key, and one appendError per hole (with its errorInfo.index)
    beside the partial data, not a compacted list or a whole-request failure.
    """
    svc = ctx.client("appsync")
    ddb = ctx.client("dynamodb")

    table, table_arn = _create_table(ctx)
    role_arn = _create_role(ctx, "appsync.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["dynamodb:BatchGetItem", "dynamodb:GetItem"],
                       "Resource": [table_arn]}],
    })
    api_id, url, key = _graphql_api(ctx, svc, SDL)

    ds_name = _alnum(ctx, "batchget")
    _poll_until(
        lambda: _try(svc.create_data_source, apiId=api_id, name=ds_name, type="AMAZON_DYNAMODB",
                     serviceRoleArn=role_arn,
                     dynamodbConfig={"tableName": table, "awsRegion": ctx.region}),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0, interval_s=5.0,
        description="CreateDataSource to stop rejecting the brand-new service role",
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="batchLookup", kind="UNIT",
        dataSourceName=ds_name, runtime=APPSYNC_JS, code=_resolver_code(table),
    )
    ctx.on_cleanup(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="batchLookup")
    )

    # ---- the prerequisite is CREATED here, never assumed -------------------------------------
    ids = [ctx.unique_name(f"k{i}-") for i in range(FANOUT)]
    values = {ids[i]: f"seeded-{i}" for i in PRESENT_INDICES}
    for present_id, value in values.items():
        ddb.put_item(
            TableName=table,
            Item={"id": {"S": present_id}, "value": {"S": value}},
        )
    absent_ids = [ids[i] for i in ABSENT_INDICES]

    document = "query B($ids: [ID!]!) { batchLookup(ids: $ids) { id value } }"

    def _ask(requested):
        return _post_json(ctx, url, {"x-api-key": key},
                          {"query": document, "variables": {"ids": requested}})

    # ---- positive control FIRST, on the keys that all exist ----------------------------------
    # It is also the endpoint/role warm gate: a brand-new service role answers with a resolver
    # error for a while, which would otherwise read as "the batch failed".
    present_ids = [ids[i] for i in PRESENT_INDICES]
    _status, control = _poll_until(
        lambda: _ask(present_ids),
        lambda res: res[0] == 200 and not res[1].get("errors")
        and len((res[1].get("data") or {}).get("batchLookup") or []) == len(PRESENT_INDICES),
        timeout_s=300.0, interval_s=5.0,
        description="the BatchGetItem resolver to serve an all-present batch on the live endpoint",
    )
    control_items = control["data"]["batchLookup"]
    for expected_id, item in zip(present_ids, control_items):
        assert item is not None and item["id"] == expected_id, (
            f"the all-present control lost its order: expected {expected_id!r}, got {item!r} in "
            f"{control_items!r}"
        )
        assert item["value"] == values[expected_id], (
            f"the control returned the wrong stored value for {expected_id!r}: expected "
            f"{values[expected_id]!r}, got {item['value']!r}"
        )

    # ---- the mixed batch: arity, order, holes, and one error per hole -------------------------
    status, body = _ask(ids)
    assert status == 200, (
        f"a partial batch result must ride a 200 GraphQL envelope, not an HTTP error: got "
        f"{status!r} body={body!r}"
    )
    items = (body.get("data") or {}).get("batchLookup")
    assert isinstance(items, list), (
        f"expected data.batchLookup to be a list even with missing keys, got {items!r} in {body!r}"
    )
    assert len(items) == FANOUT, (
        f"BatchGetItem must return one slot per REQUESTED key: expected {FANOUT} slots for "
        f"{FANOUT} keys ({len(PRESENT_INDICES)} present, {len(ABSENT_INDICES)} absent), got "
        f"{len(items)} -- a compacted list silently misaligns every client that indexes the result: "
        f"{items!r}"
    )
    for i in PRESENT_INDICES:
        assert items[i] is not None, (
            f"slot {i} was seeded and must not be null: {items!r}"
        )
        assert items[i]["id"] == ids[i], (
            f"slot {i} carries the wrong key: expected {ids[i]!r}, got {items[i]['id']!r} -- the "
            f"result list must be in the order the keys were requested: {items!r}"
        )
        assert items[i]["value"] == values[ids[i]], (
            f"slot {i} carries the wrong stored value: expected {values[ids[i]]!r}, got "
            f"{items[i]['value']!r}"
        )
    for i in ABSENT_INDICES:
        assert items[i] is None, (
            f"slot {i}'s key {ids[i]!r} was never written to {table!r}, so the slot must be null; "
            f"got {items[i]!r} in {items!r}"
        )

    errors = body.get("errors") or []
    missing_errors = [e for e in errors if e.get("errorType") == MISSING_ERROR_TYPE]
    assert len(errors) == len(ABSENT_INDICES), (
        f"expected exactly {len(ABSENT_INDICES)} appended errors -- one per missing key -- got "
        f"{len(errors)}: {errors!r}"
    )
    assert len(missing_errors) == len(ABSENT_INDICES), (
        f"every appended error must carry errorType {MISSING_ERROR_TYPE!r}, got "
        f"{[e.get('errorType') for e in errors]!r}"
    )
    named = {
        str(e.get("message", "")).split("missing:", 1)[-1]
        for e in missing_errors
    }
    assert named == set(absent_ids), (
        f"the appended errors must name exactly the keys that were absent: expected "
        f"{set(absent_ids)!r}, got {named!r} from {[e.get('message') for e in missing_errors]!r}"
    )
    reported_indices = sorted(
        (e.get("errorInfo") or {}).get("index") for e in missing_errors
    )
    assert reported_indices == sorted(ABSENT_INDICES), (
        f"errorInfo.index must report the POSITION of each hole -- a value only the server can "
        f"compute: expected {sorted(ABSENT_INDICES)!r}, got {reported_indices!r} from "
        f"{[e.get('errorInfo') for e in missing_errors]!r}"
    )
    assert not [e for e in errors if e.get("errorType") == UNPROCESSED_ERROR_TYPE], (
        f"an on-demand table well inside its capacity must serve the whole batch, so "
        f"unprocessedKeys must be empty; the resolver reported unprocessed keys: {errors!r}"
    )
    for e in missing_errors:
        assert e.get("path") == ["batchLookup"], (
            f"an appendError raised for a LIST field must carry the field's own path with no list "
            f"index -- expected {['batchLookup']!r}, got {e.get('path')!r} from {e!r}"
        )

    # ---- terminal read at the DESTINATION, through a different service and operation ----------
    direct = ddb.batch_get_item(
        RequestItems={table: {
            "Keys": [{"id": {"S": i}} for i in ids],
            "ConsistentRead": True,
        }}
    )
    assert not (direct.get("UnprocessedKeys") or {}).get(table), (
        f"the check's own BatchGetItem left keys unprocessed, so it cannot arbitrate what exists: "
        f"{direct.get('UnprocessedKeys')!r}"
    )
    found = {row["id"]["S"]: row["value"]["S"] for row in direct["Responses"][table]}
    assert found == values, (
        f"DynamoDB disagrees with the resolver about what exists in {table!r}: expected "
        f"{values!r}, got {found!r} -- so the nulls above were not genuinely absent keys"
    )
    assert all(a not in found for a in absent_ids), (
        f"the keys the resolver reported as holes must genuinely not be in the table: "
        f"{absent_ids!r} vs {sorted(found)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
