"""http-proxy-stage-variable-selects-backend-host."""

from __future__ import annotations

import json
import textwrap
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-proxy-stage-variable-selects-backend-host"

GROUP = "stage-deploy"

SERVICES = ["apigatewayv2"]

#: Shared by both backend APIs; identifies which API answered by its OWN apiId, so the front
#: API's response unambiguously names which backend served the request.
_BACKEND_HANDLER = """
import json


def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"apiId": (event.get("requestContext") or {}).get("apiId")}),
    }
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A stage variable in an HTTP_PROXY IntegrationUri substitutes the backend host, so each stage
    routes one integration to a different backend; a stage lacking the variable fails with 500.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/stage-variables.html
    """
    backend_fn = _create_lambda(ctx, _BACKEND_HANDLER)

    v2 = ctx.client("apigatewayv2")
    account = ctx.account

    backend_urls = {}
    backend_ids = {}
    for label in ("a", "b"):
        api = v2.create_api(
            Name=_name(ctx, f"httpapi-backend-{label}"), ProtocolType="HTTP", Tags=_resource_tags()
        )
        api_id, api_endpoint = api["ApiId"], api["ApiEndpoint"]
        ctx.on_cleanup(lambda api_id=api_id: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
        integ_id = v2.create_integration(
            ApiId=api_id,
            IntegrationType="AWS_PROXY",
            IntegrationUri=backend_fn["arn"],
            IntegrationMethod="POST",
            PayloadFormatVersion="2.0",
        )["IntegrationId"]
        v2.create_route(ApiId=api_id, RouteKey="$default", Target=f"integrations/{integ_id}")
        v2.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
        ctx.on_cleanup(
            lambda api_id=api_id: ctx.client("apigatewayv2").delete_stage(
                ApiId=api_id, StageName="$default"
            )
        )
        _allow_apigw_invoke(
            ctx,
            backend_fn["name"],
            f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*",
            statement_id=f"apigw-invoke-{label}",
        )
        backend_ids[label] = api_id
        backend_urls[label] = ctx.stage_url(api_endpoint, "$default")

    # IntegrationUri must start with a literal http:// or https:// (CreateIntegration refuses
    # "Invalid HTTP endpoint specified for URI" otherwise), so the scheme is the target's own and
    # the stage variable carries everything after it: host plus any route prefix the target puts
    # in front of a $default stage.
    schemes = {urllib.parse.urlsplit(u).scheme for u in backend_urls.values()}
    assert len(schemes) == 1, f"the two backend stages answered different schemes: {backend_urls!r}"
    scheme = schemes.pop()
    backend_rest = {label: u[len(scheme) + len("://"):] for label, u in backend_urls.items()}

    front = v2.create_api(
        Name=_name(ctx, "httpapi-front"), ProtocolType="HTTP", Tags=_resource_tags()
    )
    front_id, front_endpoint = front["ApiId"], front["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=front_id))
    front_integ_id = v2.create_integration(
        ApiId=front_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri=scheme + "://${stageVariables.backendUrl}/front-invoke",
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    v2.create_route(
        ApiId=front_id, RouteKey="GET /front-invoke", Target=f"integrations/{front_integ_id}"
    )
    for label, stage_name in (("a", "sa"), ("b", "sb")):
        v2.create_stage(
            ApiId=front_id,
            StageName=stage_name,
            AutoDeploy=True,
            StageVariables={"backendUrl": backend_rest[label]},
        )
        ctx.on_cleanup(
            lambda sn=stage_name: ctx.client("apigatewayv2").delete_stage(
                ApiId=front_id, StageName=sn
            )
        )
    # The negative twin: a stage that never defines `backendUrl` at all.
    v2.create_stage(ApiId=front_id, StageName="smissing", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=front_id, StageName="smissing")
    )

    for label, stage_name in (("a", "sa"), ("b", "sb")):
        status, _, text = _poll_http(
            _invoke_url(ctx, front_endpoint, stage_name, "/front-invoke"),
            accept=lambda s: s == 200,
            verify=ctx.http_verify,
            description=f"GET /front-invoke on front stage {stage_name!r} (-> backend {label!r})",
        )
        assert status == 200, (
            f"front stage {stage_name!r} expected 200 via its stage-variable-selected backend, "
            f"got {status}: {text[:300]!r}"
        )
        got_api_id = json.loads(text).get("apiId")
        assert got_api_id == backend_ids[label], (
            f"front stage {stage_name!r} (StageVariables.backendUrl == {backend_rest[label]!r}) "
            f"must route to backend {label!r} (apiId {backend_ids[label]!r}), but the response "
            f"came from apiId {got_api_id!r}"
        )

    # Negative: no `backendUrl` variable defined on this stage at all.
    status, _, text = _poll_http(
        _invoke_url(ctx, front_endpoint, "smissing", "/front-invoke"),
        # A stage still propagating answers 403/404; poll past that to the settled answer.
        accept=lambda s: s not in (None, 403, 404),
        verify=ctx.http_verify,
        description="GET /front-invoke on front stage 'smissing' (no backendUrl defined)",
    )
    assert status == 500, (
        f"an HTTP_PROXY IntegrationUri referencing an undefined stage variable must fail the "
        f"request with 500, got {status}: {text[:300]!r}"
    )
    assert json.loads(text) == {"message": "Internal Server Error"}, (
        f"expected the generic {{'message': 'Internal Server Error'}} body for an unresolved "
        f"stage variable, got {text[:300]!r}"
    )


_PREFIX = "sim2real-behav-"


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _name(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(method, url, body=None, headers=None, timeout_s=20, verify=True):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a result, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=_ssl_context(verify)) as resp:
            return (
                resp.status,
                [(k.lower(), v) for k, v in resp.getheaders()],
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            [(k.lower(), v) for k, v in exc.headers.items()],
            exc.read().decode("utf-8", "replace"),
        )


def _poll_http(
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    verify=True,
    timeout_s=150.0,
    interval_s=3.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status); return (status, headers, text). Raises on timeout.

    A new stage's execute-api DNS/TLS and deployment take seconds to propagate.
    """
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers, verify=verify)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


def _invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of an HTTP API stage."""
    p = path.lstrip("/")
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{p}"


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _name(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


def _create_lambda(ctx, handler_code, env=None, permissions=None, timeout=30):
    """Create a Lambda whose role is scoped to logs plus `permissions`, retrying through IAM role
    propagation, then wait for Active. Registers teardown for role, function and log group.
    """
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    statements.extend(permissions or [])
    role_arn = _create_role(
        ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )

    lam = ctx.client("lambda")
    name = _name(ctx, "fn")
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": 128,
        "Tags": dict(_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            # A brand-new role is not yet assumable by Lambda: the documented propagation window.
            if exc.response.get("Error", {}).get("Code") in (
                "InvalidParameterValueException",
                "AccessDeniedException",
            ):
                return None
            raise

    created = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    ctx.on_cleanup(lambda: _cleanup_log_group(ctx, f"/aws/lambda/{name}"))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _cleanup_log_group(ctx, log_group_name, timeout_s=30.0, interval_s=2.0):
    """Delete the function's log group, retrying a bounded window: the first invocation creates it
    asynchronously and delete_function never removes it.
    """
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            logs.delete_log_group(logGroupName=log_group_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            if time.monotonic() >= deadline:
                return
            time.sleep(interval_s)


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as exc:
        # Create-or-adopt: a re-run against an account that already carries the statement.
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
