"""deep-appsync-2-appsync-authz-denied-fields-nulls-only-the-denied-field."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-appsync-2-appsync-authz-denied-fields-nulls-only-the-denied-field"
GROUP = "authorization-denied"
SERVICES = ["appsync", "lambda"]

SDL = """schema { query: Query }
type Query {
    open: String
    secret: String
}
"""

OPEN_VALUE = "open-value"
SECRET_VALUE = "secret-value"

# Always isAuthorized=true; only deniedFields varies by token prefix. The field ARN comes via an env
# var built from the api ARN CreateGraphqlApi returned, so it is the ARN form AWS minted.
AUTHORIZER_SRC = '''import os


def handler(event, context):
    token = (event or {}).get("authorizationToken") or ""
    if token.startswith("short-"):
        denied = ["Query.secret"]
    elif token.startswith("arn-"):
        denied = [os.environ["SIM2REAL_DENIED_ARN"]]
    else:
        denied = []
    return {"isAuthorized": True, "deniedFields": denied, "resolverContext": {"token": token}}
'''

JS_CONST = """import { runtime } from '@aws-appsync/utils';

export function request(ctx) {
  runtime.earlyReturn('%s');
  return {};
}

export function response(ctx) {
  return ctx.result;
}
"""

APPSYNC_JS = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}


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


def _create_lambda_role(ctx):
    """An execution role for the authorizer, with its teardown registered."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-authz-role-")
    arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    return arn


def _delete_log_group_when_it_exists(ctx, group, timeout_s=150.0, quiet_s=30.0):
    """Delete a service-created log group, re-deleting until it stays gone for ``quiet_s``.

    A buffered stream can flush after the function is deleted and recreate the group."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_delete = None
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
            last_delete = time.monotonic()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "ResourceNotFoundException":
                raise RuntimeError(f"log group {group} not deleted: {code}") from exc
            if last_delete is not None and time.monotonic() - last_delete >= quiet_s:
                return
        if time.monotonic() >= deadline:
            if last_delete is None:
                raise RuntimeError(
                    f"log group {group} never materialised within {timeout_s}s"
                )
            elif time.monotonic() - last_delete < quiet_s:
                raise RuntimeError(f"log group {group} kept reappearing for {timeout_s}s")
            return
        time.sleep(3.0)


def _create_function(ctx, source, role_arn):
    """A python Lambda, its teardown, its log group's teardown, and a wait for Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-appsync-authz-fn-")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _delete_log_group_when_it_exists(ctx, f"/aws/lambda/{name}"))
    created = _poll_until(
        lambda: _try(
            lam.create_function,
            FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
            Code={"ZipFile": _zip(source)}, Timeout=20, Publish=False,
            Environment={"Variables": {"SIM2REAL_DENIED_ARN": "unset"}},
            Tags={t["Key"]: t["Value"] for t in _tags_kv()},
        ),
        # IAM reports no condition for a new trust policy becoming effective; retry the create.
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0, interval_s=5.0,
        description=f"CreateFunction {name} to stop rejecting the brand-new role",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_ready(lam, name)
    return name, created["FunctionArn"]


def _wait_function_ready(lam, name):
    cfg = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") in ("Active", "Failed")
        and c.get("LastUpdateStatus") in (None, "Successful", "Failed"),
        timeout_s=180.0, interval_s=3.0,
        description=f"Lambda {name} reaching a terminal State/LastUpdateStatus",
    )
    assert cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"), (
        f"the authorizer function is not ready: State={cfg.get('State')!r} "
        f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r} reason={cfg.get('StateReason')!r}"
    )
    return cfg


def _graphql_api(ctx, svc, sdl, **api_kwargs):
    """Create a GraphQL API + an ACTIVE schema; return (api_id, graphql_uri, api_arn)."""
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
        **api_kwargs,
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
        f"schema creation did not succeed: got {status['status']!r} "
        f"details={status.get('details')!r}"
    )
    uri = (api.get("uris") or {}).get("GRAPHQL")
    assert uri, f"the API exposed no GRAPHQL endpoint URI: {api.get('uris')!r}"
    return api_id, uri, api["arn"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Lambda authorizer returning isAuthorized=true with deniedFields yields one 200 carrying the
    permitted field and an Unauthorized error nulling only the denied field, in both the
    Type.field and field-ARN forms; an empty deniedFields before and after returns both fields.

    Reference: https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html
    """
    svc = ctx.client("appsync")
    lam = ctx.client("lambda")

    exec_role = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_function(ctx, AUTHORIZER_SRC, exec_role)

    api_id, url, api_arn = _graphql_api(
        ctx, svc, SDL,
        authenticationType="AWS_LAMBDA",
        lambdaAuthorizerConfig={"authorizerUri": fn_arn, "authorizerResultTtlInSeconds": 0},
    )
    denied_arn = f"{api_arn}/types/Query/fields/secret"

    lam.update_function_configuration(
        FunctionName=fn_name,
        Environment={"Variables": {"SIM2REAL_DENIED_ARN": denied_arn}},
    )
    cfg = _wait_function_ready(lam, fn_name)
    assert cfg["Environment"]["Variables"]["SIM2REAL_DENIED_ARN"] == denied_arn, (
        f"the authorizer did not take the denied-field ARN: {cfg.get('Environment')!r}"
    )

    lam.add_permission(
        FunctionName=fn_name, StatementId="sim2real-appsync-authorizer",
        Action="lambda:InvokeFunction", Principal="appsync.amazonaws.com", SourceArn=api_arn,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(
        FunctionName=fn_name, StatementId="sim2real-appsync-authorizer"
    ))

    ds_name = _alnum(ctx, "none")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: svc.delete_data_source(apiId=api_id, name=ds_name))
    for field, value in (("open", OPEN_VALUE), ("secret", SECRET_VALUE)):
        svc.create_resolver(
            apiId=api_id, typeName="Query", fieldName=field, kind="UNIT",
            dataSourceName=ds_name, runtime=APPSYNC_JS, code=JS_CONST % value,
        )
        ctx.on_cleanup(
            lambda f=field: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName=f)
        )

    document = {"query": "query Both { open secret }"}

    def _ask(token):
        return _post_json(ctx, url, {"Authorization": token}, document)

    # Also absorbs the 401 window while the appsync invoke permission propagates.
    ctl_status, ctl_body = _poll_until(
        lambda: _ask(ctx.unique_name("ctl-")),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors"),
        timeout_s=300.0, interval_s=5.0,
        description="the Lambda authorizer to become invocable and authorize a request",
    )
    assert ctl_body == {"data": {"open": OPEN_VALUE, "secret": SECRET_VALUE}}, (
        f"with deniedFields empty both fields must resolve and no errors key appear, got "
        f"{ctl_body!r}"
    )

    for form, prefix in (("Type.field", "short-"), ("field ARN", "arn-")):
        status, body = _ask(ctx.unique_name(prefix))
        assert status == 200, (
            f"deniedFields ({form}) must still yield HTTP 200 -- the request was authorized, only a "
            f"field was denied -- got {status!r} {body!r}"
        )
        data = body.get("data")
        assert data == {"open": OPEN_VALUE, "secret": None}, (
            f"deniedFields ({form}) must null ONLY the denied field and keep the permitted one: "
            f"expected {{'open': {OPEN_VALUE!r}, 'secret': None}}, got {data!r}"
        )
        errors = body.get("errors") or []
        assert len(errors) == 1, (
            f"deniedFields ({form}) must produce exactly one error entry, got {errors!r}"
        )
        err = errors[0]
        assert err.get("errorType") == "Unauthorized", (
            f"the denied field's error must have errorType 'Unauthorized' ({form}), got {err!r}"
        )
        assert err.get("path") == ["secret"], (
            f"the Unauthorized error must point at the denied field ({form}), got path "
            f"{err.get('path')!r}"
        )
        assert err.get("message") == "Not Authorized to access secret on type Query", (
            f"the Unauthorized error message ({form}) differs: {err.get('message')!r}"
        )

    # The denial must be per-response, not a sticky api-wide state.
    again_status, again_body = _ask(ctx.unique_name("ctl-"))
    assert again_status == 200 and again_body == {
        "data": {"open": OPEN_VALUE, "secret": SECRET_VALUE}
    }, (
        f"after the denied legs, a token with empty deniedFields must see both fields again: "
        f"{again_status!r} {again_body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
