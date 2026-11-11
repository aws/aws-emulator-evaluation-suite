"""xsvc-appsync-3-service-role-without-lambda-invoke-permission-denied."""
from __future__ import annotations

# AWS behavior this check relies on:
# When a Direct Lambda resolver's data source uses a service role
# that AppSync can assume but that has NO lambda:InvokeFunction permission, AppSync answers
# HTTP 200 with the field null and one error whose errorType is EXACTLY "Lambda:IllegalArgument"
# (stable over three requests 15 s apart), whose message quotes Lambda's own 403 naming
# "assumed-role/<role>/APPSYNC_ASSUME_ROLE" and "lambda:InvokeFunction". CreateDataSource does
# NOT validate the permission -- the failure only appears on the data plane.

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-appsync-3-service-role-without-lambda-invoke-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["appsync", "lambda"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

SDL = """schema { query: Query }
type Query {
    echo(msg: String!): String
    nope(msg: String!): String
}
"""

ECHO_SRC = '''def handler(event, context):
    return event["arguments"]["msg"]
'''


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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A data source whose service role lacks lambda:InvokeFunction fails that field with errorType
    "Lambda:IllegalArgument" (HTTP 200, field null) while a granted sibling resolves; granting
    invoke on the denied role makes the same field resolve.
    """
    svc = ctx.client("appsync")
    # The role to be refused is created FIRST, so by the time the granted one is usable its
    # trust policy has propagated at least as long -- an "unassumable role" error cannot pose as
    # the missing-permission one.
    denied_role, denied_arn = _create_role(ctx, "appsync.amazonaws.com", "deny")
    granted_role, granted_arn = _create_role(ctx, "appsync.amazonaws.com", "ds")
    _exec_role, exec_arn = _create_role(ctx, "lambda.amazonaws.com", "exec")
    _fn_name, fn_arn = _create_function(ctx, ECHO_SRC, exec_arn)
    _grant_invoke(ctx, granted_role, fn_arn)

    api_id, url, key = _graphql_api(ctx, svc, SDL)
    ok_ds = _lambda_data_source(ctx, svc, api_id, granted_arn, fn_arn)
    denied_ds = _lambda_data_source(ctx, svc, api_id, denied_arn, fn_arn)
    _direct_resolver(ctx, svc, api_id, "Query", "echo", ok_ds)
    _direct_resolver(ctx, svc, api_id, "Query", "nope", denied_ds)
    got_ds = svc.get_data_source(apiId=api_id, name=denied_ds)["dataSource"]
    assert got_ds.get("serviceRoleArn") == denied_arn, (
        f"the denied data source must carry the permissionless role: {got_ds!r}"
    )

    marker = ctx.unique_name("inv-")
    headers = {"x-api-key": key}
    variables = {"m": marker}

    # ---- beat 1: positive control ------------------------------------------------------------
    echo_q = {"query": "query Q($m: String!) { echo(msg: $m) }", "variables": variables}
    _poll_until(
        lambda: _post_json(ctx, url, headers, echo_q),
        lambda r: r[0] == 200 and (r[1].get("data") or {}).get("echo") == marker,
        timeout_s=180.0, interval_s=5.0,
        description="the granted data source to serve the marker",
    )

    # ---- beat 2: the permissionless role's field ---------------------------------------------
    both_q = {"query": "query Q($m: String!) { echo(msg: $m) nope(msg: $m) }", "variables": variables}
    status, body = _post_json(ctx, url, headers, both_q)
    assert status == 200, f"expected HTTP 200 with a partial result, got {status!r} {body!r}"
    data = body.get("data") or {}
    assert data.get("echo") == marker, f"the granted sibling must still resolve, got {data!r}"
    assert "nope" in data and data["nope"] is None, (
        f"the denied field must be present and null, got {data!r}"
    )
    errors = body.get("errors") or []
    assert len(errors) == 1, f"expected exactly one error, got {errors!r}"
    assert errors[0].get("path") == ["nope"], f"the error must name `nope`, got {errors[0]!r}"
    assert errors[0].get("errorType") == "Lambda:IllegalArgument", (
        f"expected errorType 'Lambda:IllegalArgument' for a role without lambda:InvokeFunction, "
        f"got {errors[0].get('errorType')!r} in {errors[0]!r}"
    )

    # ---- beat 3: effect absent -- Lambda refused THIS role's session, so nothing ran ---------
    message = errors[0].get("message") or ""
    assert f"assumed-role/{denied_role}/APPSYNC_ASSUME_ROLE" in message, (
        f"the refusal must name the denied role's AppSync session, got {message!r}"
    )
    assert "not authorized to perform: lambda:InvokeFunction" in message, (
        f"the refusal must be Lambda's missing-InvokeFunction denial, got {message!r}"
    )

    # ---- beat 4: repair the one missing permission; the same field now resolves --------------
    _grant_invoke(ctx, denied_role, fn_arn)
    nope_q = {"query": "query Q($m: String!) { nope(msg: $m) }", "variables": variables}
    _poll_until(
        lambda: _post_json(ctx, url, headers, nope_q),
        lambda r: r[0] == 200 and (r[1].get("data") or {}).get("nope") == marker
        and not r[1].get("errors"),
        timeout_s=240.0, interval_s=6.0,
        description="granting lambda:InvokeFunction to the denied role to let `nope` resolve",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
