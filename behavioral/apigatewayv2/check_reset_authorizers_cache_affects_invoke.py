"""reset-authorizers-cache-affects-invoke."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "reset-authorizers-cache-affects-invoke"
GROUP = "server-side"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

_AUTHORIZER_CODE = (
    "import os\n"
    "def handler(event, context):\n"
    "    allow = os.environ.get('DECISION', 'deny') == 'allow'\n"
    "    return {'isAuthorized': allow}\n"
)
_BACKEND_CODE = (
    "def handler(event, context):\n"
    "    return {'statusCode': 200, 'body': 'ok'}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A cached REQUEST authorizer decision survives a change to the authorizer's logic until
    ResetAuthorizersCache, after which the next real HTTP invoke picks up the new decision."""
    apigw = ctx.client("apigatewayv2")
    lam = ctx.client("lambda")
    region = ctx.region
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    role_arn = _create_lambda_role(ctx)

    authorizer_fn_name = ctx.unique_name("sim2real-behav-authz-fn-")
    authorizer_fn_arn = _create_function(
        ctx, lam, authorizer_fn_name, _AUTHORIZER_CODE.encode(), role_arn, {"DECISION": "deny"}
    )
    backend_fn_name = ctx.unique_name("sim2real-behav-backend-fn-")
    backend_fn_arn = _create_function(ctx, lam, backend_fn_name, _BACKEND_CODE.encode(), role_arn, {})

    _wait_lambda_active(lam, authorizer_fn_name)
    _wait_lambda_active(lam, backend_fn_name)

    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-api-"), ProtocolType="HTTP", Tags=TAGS
    )
    api_id = api["ApiId"]
    api_endpoint = api["ApiEndpoint"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    authorizer_id = apigw.create_authorizer(
        ApiId=api_id,
        AuthorizerType="REQUEST",
        AuthorizerUri=(
            f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/"
            f"{authorizer_fn_arn}/invocations"
        ),
        IdentitySource=["$request.header.Authorization"],
        Name=ctx.unique_name("sim2real-behav-authorizer-"),
        AuthorizerPayloadFormatVersion="2.0",
        EnableSimpleResponses=True,
        AuthorizerResultTtlInSeconds=300,
    )["AuthorizerId"]

    integration_id = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=backend_fn_arn,
        PayloadFormatVersion="2.0",
    )["IntegrationId"]

    apigw.create_route(
        ApiId=api_id,
        RouteKey="GET /test",
        AuthorizationType="CUSTOM",
        AuthorizerId=authorizer_id,
        Target=f"integrations/{integration_id}",
    )
    apigw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)

    lam.add_permission(
        FunctionName=authorizer_fn_name,
        StatementId="apigw-invoke-authorizer",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{region}:{account_id}:{api_id}/authorizers/{authorizer_id}",
    )
    lam.add_permission(
        FunctionName=backend_fn_name,
        StatementId="apigw-invoke-backend",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/*/test",
    )

    url = f"{api_endpoint}/test"
    token = ctx.unique_name("sim2real-behav-token-")

    # Deployed HTTP APIs with AutoDeploy apply within a handful of seconds;
    # poll until the route+authorizer chain is actually live (either a real
    # 200 or a real 403 -- both mean the request reached the authorizer).
    status_before = _poll_invoke(ctx, url, token, timeout_s=90)
    assert status_before == 403, f"expected denied (403) with DECISION=deny, got {status_before}"

    # Flip the authorizer's decision logic. This must NOT affect the already
    # cached identity source until the cache is explicitly reset.
    lam.update_function_configuration(
        FunctionName=authorizer_fn_name, Environment={"Variables": {"DECISION": "allow"}}
    )
    _wait_lambda_updated(lam, authorizer_fn_name)

    status_cached = _invoke(ctx, url, token)
    assert status_cached == 403, (
        f"expected the stale cached authorizer decision (403) to still apply "
        f"before ResetAuthorizersCache, got {status_cached}"
    )

    apigw.reset_authorizers_cache(ApiId=api_id, StageName="$default")

    status_after_reset = _poll_invoke_expect(ctx, url, token, 200, timeout_s=60)
    assert status_after_reset == 200, (
        f"expected the authorizer to be re-evaluated (200) after "
        f"ResetAuthorizersCache, got {status_after_reset}"
    )


def _zip_bytes(handler_code: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=TAGS_KV
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_function(ctx, lam, name, code: bytes, role_arn, env: dict):
    from botocore.exceptions import ClientError

    zipped = _zip_bytes(code)
    last_err = None
    for _ in range(15):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zipped},
                Environment={"Variables": env},
                Timeout=10,
                Tags=TAGS,
            )
            ctx.on_cleanup(lambda n=name: lam.delete_function(FunctionName=n))
            return resp["FunctionArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = e
            time.sleep(3)
    raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_err}")


def _wait_lambda_active(lam, name):
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=90,
        interval_s=3,
    )


def _wait_lambda_updated(lam, name):
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["LastUpdateStatus"],
        lambda s: s == "Successful",
        timeout_s=90,
        interval_s=3,
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _invoke(ctx, url: str, token: str) -> int:
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, headers={**({"Authorization": f"Bearer {token}"}), **_route})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def _poll_invoke(ctx, url: str, token: str, timeout_s: float) -> int:
    """Poll until the deployed route+authorizer chain answers with a real
    200 or 403 (as opposed to a 404 while the deployment is still propagating)."""
    return _poll_until(
        lambda: _invoke(ctx, url, token), lambda s: s in (200, 403), timeout_s=timeout_s, interval_s=3
    )


def _poll_invoke_expect(ctx, url: str, token: str, expected: int, timeout_s: float) -> int:
    return _poll_until(
        lambda: _invoke(ctx, url, token), lambda s: s == expected, timeout_s=timeout_s, interval_s=3
    )


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
