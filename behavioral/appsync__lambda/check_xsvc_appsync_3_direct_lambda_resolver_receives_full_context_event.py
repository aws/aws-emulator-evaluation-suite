"""xsvc-appsync-3-direct-lambda-resolver-receives-full-context-event."""
from __future__ import annotations

# AWS behavior this check relies on:
# A resolver on an AWS_LAMBDA data source with NO mapping templates
# and no code (a Direct Lambda resolver, operation Invoke) hands the function the whole resolver
# context as its event, with exactly these top-level keys:
#   arguments, identity, source, request, prev, info, stash
# On an API_KEY api `identity` is null; on a root Query field `source` is null; `prev` is null
# outside a pipeline; `stash` is {}; `info` carries fieldName, parentTypeName, variables,
# selectionSetList and selectionSetGraphQL; `request.headers` carries the client's headers
# (lower-cased) including x-api-key and host.

import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-appsync-3-direct-lambda-resolver-receives-full-context-event"
GROUP = "data-format"
SERVICES = ["appsync", "lambda"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

SDL = """schema { query: Query }
type Parent {
    id: ID!
    child: String
}
type Query {
    echo(msg: String!): String
    parent(id: ID!): Parent
}
"""

# Query.parent is resolved locally (NONE data source), so Parent.child -- a Direct Lambda
# resolver -- has a non-null `source` to report.
PARENT_REQUEST = '{"version": "2018-05-29", "payload": {"id": $util.toJson($context.arguments.id)}}'
PARENT_RESPONSE = "$util.toJson($context.result)"

# The function echoes its event verbatim. It holds no assertion; every assertion is in run().
ECHO_SRC = '''import json


def handler(event, context):
    return json.dumps(event)
'''

EVENT_KEYS = {"arguments", "identity", "source", "request", "prev", "info", "stash"}


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
        raise AssertionError(
            f"{DATAPLANE_MARKER}: the GraphQL endpoint {url!r} did not answer: {exc!r}"
        ) from exc
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _zip(source):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", source)
    return buf.getvalue()


def _try(fn, **kwargs):
    """The call's result, or the AWS error code -- never a bare False."""
    try:
        return fn(**kwargs)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "UnknownError")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchEntity",):
            raise RuntimeError(
                f"role {role_name} not deleted: {exc.response.get('Error', {}).get('Code')}"
            ) from exc


def _create_role(ctx, trust_service, label):
    """An IAM role trusted by ``trust_service`` with NO permissions, teardown registered."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-xsvc-appsync3-{label}-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    return role_name, arn


def _grant_invoke(ctx, role_name, function_arn):
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name, PolicyName="invoke-one-function",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction",
                           "Resource": function_arn}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(
        RoleName=role_name, PolicyName="invoke-one-function"))


def _reap_log_group(ctx, group, window_s=20.0):
    """Delete the function's log group in a LOOP over a bounded window, never raising.

    The execution role carries no logs:* permission, so the group should never exist; the loop
    still re-deletes anything that materialises (a late flush recreates a deleted group).
    """
    logs = ctx.client("logs")
    deadline = time.monotonic() + window_s
    seen = False
    while time.monotonic() < deadline:
        try:
            logs.delete_log_group(logGroupName=group)
            seen = True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "ResourceNotFoundException":
                raise RuntimeError(f"log group {group} not deleted: {code}") from exc
        time.sleep(4.0)
    if seen:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _create_function(ctx, source, role_arn):
    """A python Lambda with teardown registered BEFORE the create's follow-ups, waited Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-appsync3-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    created = _poll_until(
        lambda: _try(
            lam.create_function,
            FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
            Code={"ZipFile": _zip(source)}, Timeout=15, Publish=False,
            Tags={t["Key"]: t["Value"] for t in _tags_kv()},
        ),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0, interval_s=5.0,
        description=f"CreateFunction {name} to stop rejecting the brand-new role",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    state = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=180.0, interval_s=3.0,
        description=f"Lambda {name} reaching a terminal State",
    )
    assert state["State"] == "Active", (
        f"the function did not become Active: {state.get('State')!r} {state.get('StateReason')!r}"
    )
    return name, created["FunctionArn"]


def _graphql_api(ctx, svc, sdl):
    """Create an API_KEY GraphQL API + an ACTIVE schema + a key -> (api_id, uri, key)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-xsvc-appsync3-api-"),
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
        f"schema creation did not succeed: got {status['status']!r} {status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    key = svc.create_api_key(apiId=api_id, description="sim2real-xsvc appsync3 key")["apiKey"]["id"]
    ctx.on_cleanup(lambda: svc.delete_api_key(apiId=api_id, id=key))
    return api_id, uri, key


def _lambda_data_source(ctx, svc, api_id, role_arn, function_arn):
    ds_name = _alnum(ctx, "fn_")
    svc.create_data_source(
        apiId=api_id, name=ds_name, type="AWS_LAMBDA", serviceRoleArn=role_arn,
        lambdaConfig={"lambdaFunctionArn": function_arn},
    )
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    return ds_name


def _direct_resolver(ctx, svc, api_id, type_name, field, ds_name):
    """A Direct Lambda resolver: no request/response templates, no code."""
    svc.create_resolver(apiId=api_id, typeName=type_name, fieldName=field, dataSourceName=ds_name)
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName=type_name, fieldName=field))


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Direct Lambda resolver hands the function the whole resolver context (exactly arguments /
    identity / source / request / prev / info / stash) carrying this request's values and headers,
    and a nested field receives its parent's resolved value as `source`.
    """
    svc = ctx.client("appsync")
    _exec_role, exec_arn = _create_role(ctx, "lambda.amazonaws.com", "exec")
    appsync_role, appsync_arn = _create_role(ctx, "appsync.amazonaws.com", "ds")
    _fn_name, fn_arn = _create_function(ctx, ECHO_SRC, exec_arn)
    _grant_invoke(ctx, appsync_role, fn_arn)

    api_id, url, key = _graphql_api(ctx, svc, SDL)
    ds_name = _lambda_data_source(ctx, svc, api_id, appsync_arn, fn_arn)
    _direct_resolver(ctx, svc, api_id, "Query", "echo", ds_name)
    _direct_resolver(ctx, svc, api_id, "Parent", "child", ds_name)
    none_ds = _alnum(ctx, "none_")
    svc.create_data_source(apiId=api_id, name=none_ds, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=none_ds))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="parent", dataSourceName=none_ds,
        requestMappingTemplate=PARENT_REQUEST, responseMappingTemplate=PARENT_RESPONSE,
    )
    ctx.on_cleanup(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="parent"))
    got_resolver = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    assert not got_resolver.get("requestMappingTemplate") and not got_resolver.get("code"), (
        f"the echo resolver must be a Direct Lambda resolver (no template, no code): {got_resolver!r}"
    )

    marker = ctx.unique_name("evt-")
    header_marker = ctx.unique_name("hdr-")
    query = {
        "query": "query Q($m: String!, $p: ID!) { echo(msg: $m) parent(id: $p) { id child } }",
        "variables": {"m": marker, "p": f"p-{marker}"},
    }
    headers = {"x-api-key": key, "x-sim2real-marker": header_marker}

    # The resolver and the role grant settle asynchronously, so poll for the VALUE.
    status, body = _poll_until(
        lambda: _post_json(ctx, url, headers, query),
        lambda r: r[0] == 200 and not r[1].get("errors")
        and (r[1].get("data") or {}).get("echo") is not None,
        timeout_s=180.0, interval_s=5.0,
        description="the Direct Lambda resolvers to serve the query without errors",
    )
    event = json.loads(body["data"]["echo"])

    # ---- beat 1: exactly the documented top-level keys --------------------------------------
    assert set(event) == EVENT_KEYS, (
        f"Direct Lambda event keys: expected {sorted(EVENT_KEYS)!r}, got {sorted(event)!r}"
    )

    # ---- beat 2: this request's values, and the nulls that follow from the wiring ------------
    assert event["arguments"] == {"msg": marker}, f"arguments: got {event['arguments']!r}"
    assert event["identity"] is None, f"identity under API_KEY must be null, got {event['identity']!r}"
    assert event["source"] is None, f"source of a root field must be null, got {event['source']!r}"
    assert event["prev"] is None, f"prev outside a pipeline must be null, got {event['prev']!r}"
    assert event["stash"] == {}, f"stash must start empty, got {event['stash']!r}"
    info = event["info"]
    assert info.get("fieldName") == "echo" and info.get("parentTypeName") == "Query", (
        f"info must name Query.echo, got {info!r}"
    )
    assert info.get("variables") == query["variables"], (
        f"info.variables: expected {query['variables']!r}, got {info.get('variables')!r}"
    )
    assert info.get("selectionSetList") == [] and info.get("selectionSetGraphQL") == "", (
        f"a scalar field has an empty selection set, got {info!r}"
    )

    # ---- beat 3: the client's headers are forwarded ------------------------------------------
    req_headers = (event["request"] or {}).get("headers") or {}
    assert req_headers.get("x-api-key") == key, (
        f"request.headers x-api-key: expected {key!r}, got {req_headers.get('x-api-key')!r}"
    )
    assert req_headers.get("x-sim2real-marker") == header_marker, (
        f"request.headers must carry the client's custom header {header_marker!r}, got "
        f"{req_headers.get('x-sim2real-marker')!r}"
    )
    assert req_headers.get("host") == urllib.parse.urlparse(url).netloc, (
        f"request.headers host: expected {urllib.parse.urlparse(url).netloc!r}, got "
        f"{req_headers.get('host')!r}"
    )

    # ---- beat 4: a nested field receives its parent as `source` ------------------------------
    parent = body["data"]["parent"]
    assert parent and parent.get("id") == f"p-{marker}", f"parent: got {parent!r}"
    child_event = json.loads(parent["child"])
    assert set(child_event) == EVENT_KEYS, (
        f"nested Direct Lambda event keys: expected {sorted(EVENT_KEYS)!r}, got {sorted(child_event)!r}"
    )
    assert child_event["source"] == {"id": f"p-{marker}"}, (
        f"nested field source: expected the parent's resolved value, got {child_event['source']!r}"
    )
    assert child_event["arguments"] == {}, f"child has no arguments, got {child_event['arguments']!r}"
    assert child_event["info"].get("fieldName") == "child", f"got {child_event['info']!r}"
    assert child_event["info"].get("parentTypeName") == "Parent", f"got {child_event['info']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
