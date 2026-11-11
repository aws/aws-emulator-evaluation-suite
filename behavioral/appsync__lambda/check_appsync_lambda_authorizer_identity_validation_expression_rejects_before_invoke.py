"""appsync-lambda-authorizer-identity-validation-expression-rejects-before-invoke."""
from __future__ import annotations

# AWS behavior this check relies on: a Lambda authorizer's identityValidationExpression is a
# regular expression tested against the authorization token BEFORE the Lambda function is
# called. A token that does not match it is refused with 401 Unauthorized even when the
# authorizer function itself would unconditionally authorize every token -- so the regex gate
# runs ahead of, and independently from, whatever the function returns. A matching token still
# reaches the function.

import io
import json
import re
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appsync-lambda-authorizer-identity-validation-expression-rejects-before-invoke"
GROUP = "overly-permissive"
SERVICES = ["appsync", "lambda"]

IDENTITY_VALIDATION_EXPRESSION = r"^sim2real-ok-.*$"
AUTHORIZER_LOG_PREFIX = "AUTHORIZER-RAN"

SDL = """schema { query: Query }
type Query {
    echo(marker: String!): String
}
"""

# No mapping template calls the backend at all: the ONLY work this resolver does is hand back
# the argument it was given, so the check's assertions are entirely about the authorizer gate.
ECHO_REQUEST = '{"version": "2018-05-29"}'
ECHO_RESPONSE = "$util.toJson($context.arguments.marker)"

# Unconditionally authorizes EVERY token -- so a 401 on a non-matching token can only be the
# identityValidationExpression gate, never this function's own logic.
AUTHORIZER_SRC = f'''def handler(event, context):
    token = (event or {{}}).get("authorizationToken") or ""
    print({AUTHORIZER_LOG_PREFIX!r} + " " + token)
    return {{"isAuthorized": True}}
'''


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=180.0, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout -- never returns its last value."""
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
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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
        raise AssertionError(f"the GraphQL endpoint {url!r} did not answer: {exc!r}") from exc
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
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code != "NoSuchEntity":
            raise RuntimeError(f"role {role_name} not deleted: {code}") from exc


def _create_role(ctx, trust_service, managed_policies=()):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-appsync-idve-role-")
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
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return arn


def _create_function(ctx, source, role_arn):
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-appsync-idve-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    created = _poll_until(
        ctx,
        lambda: _try(
            lam.create_function,
            FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
            Code={"ZipFile": _zip(source)}, Timeout=15, Publish=False,
            Tags={t["Key"]: t["Value"] for t in _tags_kv()},
        ),
        lambda outcome: isinstance(outcome, dict),
        timeout_s=180.0,
        description=f"CreateFunction {name} to stop rejecting the brand-new role",
    )
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    state = _poll_until(
        ctx,
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=180.0,
        description=f"Lambda {name} reaching a terminal State",
    )
    assert state["State"] == "Active", (
        f"the function did not become Active: {state.get('State')!r} {state.get('StateReason')!r}"
    )
    return name, created["FunctionArn"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; never created
    at all is three clean reads away, not a failure."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _log_messages(ctx, function_name, needle):
    """Every log message in the function's group containing ``needle``; an absent group means
    no events rather than an error."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"
    out = []
    try:
        paginator = logs.get_paginator("filter_log_events")
        for page in paginator.paginate(logGroupName=group, filterPattern=f'"{needle}"'):
            out.extend(e.get("message", "") for e in page.get("events", []))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return []
        raise
    return out


def _graphql_api(ctx, svc, sdl, **api_kwargs):
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-idve-api-"),
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
        **api_kwargs,
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(_teardown(lambda: svc.delete_graphql_api(apiId=api_id), "NotFoundException"))
    svc.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    status = _poll_until(
        ctx,
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED"),
        timeout_s=180.0,
        description="StartSchemaCreation to reach a terminal status",
    )
    assert status["status"] in ("SUCCESS", "ACTIVE"), f"schema creation failed: {status!r}"
    uris = api.get("uris") or {}
    assert uris.get("GRAPHQL"), f"the API exposed no GRAPHQL endpoint URI: {uris!r}"
    return api_id, uris, api["arn"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda authorizer's identityValidationExpression refuses a non-matching token with 401
    before the function runs, even though the function would authorize every token it receives;
    a matching token still reaches it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-appsync-api-lambdaauthorizerconfig.html
    """
    svc = ctx.client("appsync")
    lam = ctx.client("lambda")

    exec_role = _create_role(
        ctx, "lambda.amazonaws.com",
        managed_policies=("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",),
    )
    authorizer_name, authorizer_arn = _create_function(ctx, AUTHORIZER_SRC, exec_role)

    api_id, uris, api_arn = _graphql_api(
        ctx, svc, SDL,
        authenticationType="AWS_LAMBDA",
        lambdaAuthorizerConfig={
            "authorizerUri": authorizer_arn,
            "authorizerResultTtlInSeconds": 0,
            "identityValidationExpression": IDENTITY_VALIDATION_EXPRESSION,
        },
    )
    graphql_uri = uris["GRAPHQL"]

    lam.add_permission(
        FunctionName=authorizer_name, StatementId="sim2real-appsync-authorizer",
        Action="lambda:InvokeFunction", Principal="appsync.amazonaws.com", SourceArn=api_arn,
    )
    ctx.on_cleanup(_teardown(
        lambda: lam.remove_permission(
            FunctionName=authorizer_name, StatementId="sim2real-appsync-authorizer"
        ), "ResourceNotFoundException"))

    none_ds = ctx.unique_name("none_ds").replace("-", "_")
    svc.create_data_source(apiId=api_id, name=none_ds, type="NONE")
    ctx.on_cleanup(_teardown(
        lambda: svc.delete_data_source(apiId=api_id, name=none_ds), "NotFoundException"))
    svc.create_resolver(
        apiId=api_id, typeName="Query", fieldName="echo", dataSourceName=none_ds,
        requestMappingTemplate=ECHO_REQUEST, responseMappingTemplate=ECHO_RESPONSE,
    )
    ctx.on_cleanup(_teardown(
        lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="echo"), "NotFoundException"))

    query = "query Echo($marker: String!) { echo(marker: $marker) }"
    warm_marker = ctx.unique_name("warm-")
    rejected_marker = ctx.unique_name("rejected-")
    allowed_marker = ctx.unique_name("allowed-")

    def _ask(token, marker):
        return _post_json(ctx, graphql_uri, {"Authorization": token},
                          {"query": query, "variables": {"marker": marker}})

    # ---- barrier FIRST: prove the matching-token path is live before any denial is asserted --
    # lambda:InvokeFunction for appsync.amazonaws.com propagates asynchronously; during that
    # window every token (matching or not) answers 401, which would make the denial below mean
    # nothing.
    warm_status, warm_body = _poll_until(
        ctx,
        lambda: _ask(f"sim2real-ok-{warm_marker}", warm_marker),
        lambda res: res[0] == 200 and not (res[1] or {}).get("errors")
        and ((res[1] or {}).get("data") or {}).get("echo") == warm_marker,
        timeout_s=180.0,
        description="a matching-regex token to clear the authorizer and reach the resolver",
    )
    assert warm_body["data"]["echo"] == warm_marker, f"warm-up echo mismatch: {warm_body!r}"

    # ---- break exactly one thing: a token that does NOT match identityValidationExpression ----
    rejected_token = f"sim2real-nope-{rejected_marker}"
    assert not re.match(IDENTITY_VALIDATION_EXPRESSION, rejected_token), (
        f"test bug: {rejected_token!r} must not match {IDENTITY_VALIDATION_EXPRESSION!r}"
    )
    rejected_status, rejected_body = _ask(rejected_token, rejected_marker)
    assert rejected_status == 401, (
        f"a token failing identityValidationExpression must be refused at the transport before "
        f"the always-authorizing function could run; got {rejected_status!r} {rejected_body!r}"
    )
    rejected_errors = rejected_body.get("errors") or []
    assert len(rejected_errors) == 1, (
        f"expected exactly one error on the regex rejection, got {rejected_errors!r}"
    )
    assert rejected_errors[0].get("errorType") == "UnauthorizedException", (
        f"the regex rejection carried the wrong errorType: {rejected_errors[0]!r}"
    )
    assert rejected_errors[0].get("message") == "You are not authorized to make this call.", (
        f"the regex rejection carried the wrong message: {rejected_errors[0]!r}"
    )
    assert "data" not in rejected_body, (
        f"the regex-refused request still returned a GraphQL data envelope: {rejected_body!r}"
    )

    # ---- positive control: a matching token issued AFTER the denial still reaches the function
    allowed_token = f"sim2real-ok-{allowed_marker}"
    allowed_status, allowed_body = _ask(allowed_token, allowed_marker)
    assert allowed_status == 200 and not allowed_body.get("errors"), (
        f"the control leg after the denial did not succeed: {allowed_status!r} {allowed_body!r}"
    )
    assert allowed_body["data"]["echo"] == allowed_marker, (
        f"the control leg did not echo its own marker: {allowed_body!r}"
    )

    # ---- the barrier: the control invocation's log line has been delivered --------------------
    _poll_until(
        ctx,
        lambda: _log_messages(ctx, authorizer_name, AUTHORIZER_LOG_PREFIX),
        lambda msgs: any(allowed_token in m for m in msgs),
        timeout_s=150.0,
        description="the control invocation's authorizer log line to be delivered",
    )

    # ---- and the effect is absent: the regex-refused token never reached the function ---------
    invoked_for = _log_messages(ctx, authorizer_name, AUTHORIZER_LOG_PREFIX)
    assert any(allowed_token in m for m in invoked_for), (
        f"the barrier passed but the control token is gone from the log: {invoked_for!r}"
    )
    assert not any(rejected_token in m for m in invoked_for), (
        f"the function RAN for the token the regex should have refused -- its log line is "
        f"present, and log delivery for this function is demonstrably current because the "
        f"control invocation's own line just arrived: {invoked_for!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
