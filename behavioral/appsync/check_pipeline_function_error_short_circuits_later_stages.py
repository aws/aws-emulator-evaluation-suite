"""pipeline-function-error-short-circuits-later-stages."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-function-error-short-circuits-later-stages"
GROUP = "server-side"
SERVICES = ["appsync"]

SDL = """schema { query: Query }
type Query {
    staged(msg: String!): Int
}
"""

FLIP_TIMEOUT_S = 180.0

# Each stage ADDs 1 to its OWN counter item, so "did stage N run" is answerable at DynamoDB and
# not merely at AppSync. STAGE_ID is substituted per function.
JS_STAGE_OK = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'UpdateItem',
    key: util.dynamodb.toMapValues({ id: 'STAGE_ID' }),
    update: {
      expression: 'ADD #v :inc',
      expressionNames: { '#v': 'value' },
      expressionValues: util.dynamodb.toMapValues({ ':inc': 1 }),
    },
  };
}

export function response(ctx) {
  if (ctx.error) {
    util.error(ctx.error.message, ctx.error.type);
  }
  return ctx.result.value;
}
"""

# Byte-identical to JS_STAGE_OK except for the ONE raise in the response handler.
JS_STAGE_FAILS = """import { util } from '@aws-appsync/utils';

export function request(ctx) {
  return {
    operation: 'UpdateItem',
    key: util.dynamodb.toMapValues({ id: 'STAGE_ID' }),
    update: {
      expression: 'ADD #v :inc',
      expressionNames: { '#v': 'value' },
      expressionValues: util.dynamodb.toMapValues({ ':inc': 1 }),
    },
  };
}

export function response(ctx) {
  util.error('sim2real-halt', 'SimParityPipelineHalt');
}
"""

JS_PIPELINE_BEFORE_AFTER = """export function request(ctx) {
  return {};
}

export function response(ctx) {
  return ctx.prev.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
ERROR_TYPE = "SimParityPipelineHalt"
STAGES = ("stage1", "stage2", "stage3")


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


def _poll_until_stable(probe, predicate, *, stable_n, timeout_s=180.0, interval_s=5.0,
                        description="condition"):
    """Like ``_poll_until``, but requires ``stable_n`` CONSECUTIVE matching probes: UpdateFunction's
    new code reaches AppSync's data plane non-atomically, so one match does not mean it settled."""
    deadline = time.monotonic() + timeout_s
    streak = 0
    last = None
    while time.monotonic() < deadline:
        last = probe()
        streak = streak + 1 if predicate(last) else 0
        if streak >= stable_n:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not stable ({stable_n} consecutive matching probes) within {timeout_s}s. "
        f"Last result: {last!r}, longest streak reached: {streak}"
    )


def _alnum(ctx, prefix):
    """AppSync DataSource/Function names are ``[_A-Za-z][_0-9A-Za-z]*`` -- no hyphens."""
    return ctx.unique_name(prefix).replace("-", "_")


def _post_json(ctx, url, headers, payload, timeout_s=30):
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
    """The call's result, or the AWS error code, so a poll timeout names what blocked it."""
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

    IAM exposes no propagation condition, so the bounded retry at first use absorbs it.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-pipe-role-")
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


def _create_counter_table(ctx, counter_ids):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-appsync-stagectr-")
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
    for cid in counter_ids:
        ddb.put_item(TableName=name, Item={"id": {"S": cid}, "value": {"N": "0"}})
    return name, arn


def _counters(ctx, table, counter_ids):
    """Every stage counter's current value, read directly from DynamoDB with GetItem."""
    ddb = ctx.client("dynamodb")
    out = {}
    for cid in counter_ids:
        item = ddb.get_item(
            TableName=table, Key={"id": {"S": cid}}, ConsistentRead=True
        ).get("Item")
        assert item, (
            f"counter item {cid!r} is missing from {table!r}; the check seeded it, so this is a "
            f"lost write, not an absent prerequisite"
        )
        out[cid] = int(item["value"]["N"])
    return out


def _graphql_api(ctx, svc, sdl):
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
    key = svc.create_api_key(apiId=api_id, description="sim2real-behav pipeline key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))
    return api_id, uri, key


def _stage_name(svc, api_id, function_id):
    """The function's current name, which UpdateFunction requires; a new one would rename it."""
    return svc.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]["name"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A pipeline function whose response handler calls util.error() halts the pipeline: HTTP 200
    with the error envelope, stage 1's DynamoDB write lands but later stages never run; restoring
    stage 1 makes the identical request run all three stages again.
    """
    svc = ctx.client("appsync")
    table, table_arn = _create_counter_table(ctx, list(STAGES))
    role_arn = _create_role(ctx, "appsync.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["dynamodb:UpdateItem"],
                       "Resource": [table_arn]}],
    })
    api_id, url, key = _graphql_api(ctx, svc, SDL)

    ds_name = _alnum(ctx, "ctr")
    _poll_until(
        lambda: _try(svc.create_data_source, apiId=api_id, name=ds_name, type="AMAZON_DYNAMODB",
                     serviceRoleArn=role_arn,
                     dynamodbConfig={"tableName": table, "awsRegion": ctx.region}),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=FLIP_TIMEOUT_S, interval_s=5.0,
        description="CreateDataSource to stop rejecting the brand-new service role",
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))

    function_ids = []
    for stage in STAGES:
        fn = svc.create_function(
            apiId=api_id, name=_alnum(ctx, stage + "_"), dataSourceName=ds_name,
            runtime=APPSYNC_JS, code=JS_STAGE_OK.replace("STAGE_ID", stage),
        )["functionConfiguration"]
        ctx.on_cleanup(
            lambda _i=fn["functionId"]: svc.delete_function(apiId=api_id, functionId=_i)
        )
        function_ids.append(fn["functionId"])

    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="staged", kind="PIPELINE",
        pipelineConfig={"functions": function_ids},
        runtime=APPSYNC_JS, code=JS_PIPELINE_BEFORE_AFTER,
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="staged"))

    ordered = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="staged")["resolver"]
    assert (ordered.get("pipelineConfig") or {}).get("functions") == function_ids, (
        f"GetResolver reordered or dropped the pipeline: expected {function_ids!r}, got "
        f"{(ordered.get('pipelineConfig') or {}).get('functions')!r}"
    )

    marker = ctx.unique_name("halt-")
    document = "query S($m: String!) { staged(msg: $m) }"

    def _ask():
        return _post_json(ctx, url, {"x-api-key": key},
                          {"query": document, "variables": {"m": marker}})

    # Counters are read around ONE request after the poll, so the poll's own requests do not
    # advance the counters being compared.
    def _one_shot():
        pre = _counters(ctx, table, STAGES)
        status, body = _ask()
        post = _counters(ctx, table, STAGES)
        return status, body, {s: post[s] - pre[s] for s in STAGES}, pre, post

    # ---- beat 1: the healthy pipeline, and every stage really ran ----------------------------
    _poll_until(
        _ask,
        lambda res: res[0] == 200 and isinstance((res[1].get("data") or {}).get("staged"), int),
        timeout_s=FLIP_TIMEOUT_S, interval_s=5.0,
        description="the healthy three-stage pipeline to resolve through the live endpoint",
    )
    ok_status, ok, deltas, _pre, healthy = _one_shot()
    assert ok_status == 200 and not ok.get("errors"), (
        f"the healthy pipeline returned errors: {ok_status!r} {ok!r}"
    )
    assert deltas == dict.fromkeys(STAGES, 1), (
        f"one healthy request must run each of the three stages exactly once: per-stage deltas "
        f"{deltas!r}"
    )
    assert ok["data"]["staged"] == healthy[STAGES[-1]], (
        f"the field must return the LAST stage's value: stage3 counter is "
        f"{healthy[STAGES[-1]]}, the response said {ok['data']['staged']!r}"
    )

    # ---- beat 2: break exactly one thing -- stage 1's response handler -----------------------
    svc.update_function(
        apiId=api_id, name=_stage_name(svc, api_id, function_ids[0]),
        functionId=function_ids[0], dataSourceName=ds_name, runtime=APPSYNC_JS,
        code=JS_STAGE_FAILS.replace("STAGE_ID", STAGES[0]),
    )

    # ---- beat 3: the specific refusal --------------------------------------------------------
    # The data plane adopts UpdateFunction's code non-atomically, so require 3 consecutive halts.
    _poll_until_stable(
        _ask,
        lambda res: res[0] == 200 and bool(res[1].get("errors")),
        stable_n=3, timeout_s=FLIP_TIMEOUT_S, interval_s=5.0,
        description="stage 1's new code to reach the data plane and halt the pipeline",
    )
    halt_status, halted, halt_deltas, pre_halt, post_halt = _one_shot()
    assert halt_status == 200, (
        f"a field error rides a 200 GraphQL envelope: expected 200, got {halt_status!r} "
        f"body={halted!r}"
    )
    halt_errors = halted.get("errors") or []
    assert len(halt_errors) == 1, (
        f"expected exactly one error from the halted pipeline, got {len(halt_errors)}: "
        f"{halt_errors!r}"
    )
    assert halt_errors[0].get("errorType") == ERROR_TYPE, (
        f"expected errorType {ERROR_TYPE!r} -- the second argument of util.error -- got "
        f"{halt_errors[0].get('errorType')!r} in {halt_errors[0]!r}"
    )
    assert halt_errors[0].get("path") == ["staged"], (
        f"expected errors[0].path to name the field, got {halt_errors[0].get('path')!r}"
    )
    assert (halted.get("data") or {}).get("staged", "missing") is None, (
        f"the halted field must be null in the data envelope, got "
        f"{(halted.get('data') or {}).get('staged', 'missing')!r} in {halted!r}"
    )

    # ---- beat 4: effect absent at the destination, behind stage 1's own increment ------------
    assert halt_deltas[STAGES[0]] == 1, (
        f"stage 1's request handler was left untouched, so its DynamoDB write MUST have landed; "
        f"without it the absences below would only prove the request never arrived. Expected "
        f"{STAGES[0]} to advance by exactly 1 from {pre_halt[STAGES[0]]}, got "
        f"{post_halt[STAGES[0]]}"
    )
    for later in STAGES[1:]:
        assert halt_deltas[later] == 0, (
            f"stage 1 raised, so {later} must never have run: expected its counter to stay at "
            f"{pre_halt[later]}, got {post_halt[later]} (stage1 went "
            f"{pre_halt[STAGES[0]]}->{post_halt[STAGES[0]]} in the same request, so the request "
            f"did reach the pipeline)"
        )

    # ---- beats 5 and 6: restore, and the identical request works again -----------------------
    svc.update_function(
        apiId=api_id, name=_stage_name(svc, api_id, function_ids[0]),
        functionId=function_ids[0], dataSourceName=ds_name, runtime=APPSYNC_JS,
        code=JS_STAGE_OK.replace("STAGE_ID", STAGES[0]),
    )
    # Same non-atomic propagation as the halt: require 3 consecutive clean probes.
    _poll_until_stable(
        _ask,
        lambda res: res[0] == 200 and not res[1].get("errors")
        and isinstance((res[1].get("data") or {}).get("staged"), int),
        stable_n=3, timeout_s=FLIP_TIMEOUT_S, interval_s=5.0,
        description="restoring stage 1 to let the identical request through again",
    )
    r_status, restored, restore_deltas, _pre_r, _post_r = _one_shot()
    assert r_status == 200 and not restored.get("errors"), (
        f"the restored pipeline still returned errors: {r_status!r} {restored!r}"
    )
    assert isinstance(restored["data"]["staged"], int), (
        f"the restored pipeline returned a null field: {restored!r}"
    )
    assert restore_deltas == dict.fromkeys(STAGES, 1), (
        f"after the restore one request must run each stage exactly once again: deltas "
        f"{restore_deltas!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
