"""apigw-request-authorizer-secret-rotation-changes-accepted-key."""
from __future__ import annotations

import io
import json
import random
import ssl
import string
import textwrap
import time
import urllib.parse
import zipfile
from http.client import HTTPConnection, HTTPSConnection

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigw-request-authorizer-secret-rotation-changes-accepted-key"
GROUP = "authorizers"
SERVICES = ["apigateway", "lambda", "secretsmanager"]

_PREFIX = "sim2real-xsvc-"

_AUTHORIZER_CODE = """
import boto3

_client = boto3.client("secretsmanager")


def handler(event, context):
    headers = event.get("headers") or {}
    presented = None
    for name, value in headers.items():
        if name.lower() == "x-app-key":
            presented = value
    secret_id = event["stageVariables"]["secretId"]
    expected = _client.get_secret_value(SecretId=secret_id)["SecretString"]
    effect = "Allow" if presented == expected else "Deny"
    return {
        "principalId": "sim2real-authz-user",
        "policyDocument": {"Version": "2012-10-17", "Statement": [{
            "Action": "execute-api:Invoke", "Effect": effect, "Resource": event["methodArn"]}]},
    }
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A REST REQUEST authorizer reads its comparison key fresh from Secrets Manager on every
    call (TTL 0): a key valid before a rotation is denied after it, and the new value admits
    immediately, with no redeploy of the API or the authorizer.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_update-secret-value.html
    """
    secret_arn, old_key = _create_secret(ctx)
    fn = _create_authorizer_fn(ctx, secret_arn)
    api_id, _root_id, _authorizer_id = _wire_api(ctx, fn, secret_arn)

    url = _rest_invoke_url(ctx, api_id, "live", "/secure")

    status, _h, text = _poll(url, {"x-app-key": old_key}, lambda s, t: s == 200,
                             verify=ctx.http_verify,
                             description="GET /secure with the pre-rotation key")
    assert status == 200 and text == '{"served":true}', (
        f"the pre-rotation key must be admitted, got {status}: {text[:300]!r}")

    new_key = f"sim2real{_unique_token(24)}"
    assert new_key != old_key, "generated rotation key collided with the original"
    sm = ctx.client("secretsmanager")
    sm.put_secret_value(SecretId=secret_arn, SecretString=new_key)

    status, _h, text = _poll(url, {"x-app-key": old_key}, lambda s, t: s == 403,
                             verify=ctx.http_verify,
                             description="GET /secure with the now-stale key, after rotation")
    assert status == 403, f"a key valid before rotation must be denied after it, got {status}: {text[:300]!r}"
    assert text == (
        '{"Message":"User is not authorized to access this resource with an explicit deny '
        'in an identity-based policy"}'
    ), f"unexpected 403 body for the stale key: {text[:300]!r}"

    status, _h, text = _http("GET", url, headers={"x-app-key": new_key}, verify=ctx.http_verify)
    assert status == 200 and text == '{"served":true}', (
        f"the rotated-in key must be admitted immediately, got {status}: {text[:300]!r}")


def _unique_token(length: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _xtags() -> dict:
    return {"sim2real": CHECK, "sim2real:managed": "true"}


def _retry_throttled(fn, *, attempts=10):
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)))


def _create_secret(ctx):
    sm = ctx.client("secretsmanager")
    name = _xname(ctx, "secret")
    key = f"sim2real{_unique_token(24)}"
    resp = sm.create_secret(Name=name, SecretString=key,
                            Tags=[{"Key": k, "Value": v} for k, v in _xtags().items()])
    arn = resp["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn, key


def _delete_role(iam, role_name):
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _reap_log_group(logs, name, *, reads=3, interval_s=5.0, budget_s=180.0):
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
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
                raise AssertionError(f"log group {name} kept reappearing after delete")
            time.sleep(interval_s)


def _create_authorizer_fn(ctx, secret_arn):
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _xtags().items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="access", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                           "logs:PutLogEvents"], "Resource": "arn:aws:logs:*:*:*"},
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
        ]}))

    name = _xname(ctx, "authz-fn")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(_AUTHORIZER_CODE))
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.handler", Code={"ZipFile": buf.getvalue()},
                Timeout=15, MemorySize=128, Tags=_xtags())["FunctionArn"]
            break
        except ClientError as exc:
            if (exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException"
                    or time.monotonic() >= deadline):
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return {"name": name, "arn": arn}


def _wire_api(ctx, fn, secret_arn):
    ag = ctx.client("apigateway")
    account = ctx.client("sts").get_caller_identity()["Account"]
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=_xname(ctx, "api"), endpointConfiguration={"types": ["REGIONAL"]},
        tags=_xtags()))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))
    root_id = next(r["id"] for r in ag.get_resources(restApiId=api_id)["items"] if r["path"] == "/")

    authorizer_id = _retry_throttled(lambda: ag.create_authorizer(
        restApiId=api_id, name=_xname(ctx, "authz"), type="REQUEST",
        identitySource="method.request.header.x-app-key",
        authorizerUri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
                       f"{fn['arn']}/invocations"),
        authorizerResultTtlInSeconds=0))["id"]

    ctx.client("lambda").add_permission(
        FunctionName=fn["name"], StatementId="apigw-invoke", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/authorizers/{authorizer_id}")

    resource_id = _retry_throttled(lambda: ag.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="secure"))["id"]
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        authorizationType="CUSTOM", authorizerId=authorizer_id))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": '{"served":true}'}))

    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName="live", deploymentId=deployment_id,
        variables={"secretId": secret_arn}, tags=_xtags()))
    ctx.on_cleanup(lambda: _retry_throttled(
        lambda: ag.delete_stage(restApiId=api_id, stageName="live")))
    return api_id, root_id, authorizer_id


def _delete_rest_api(ag, api_id, *, budget_s=150.0):
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def _rest_invoke_url(ctx, api_id, stage, path):
    return f"{ctx.rest_api_url(api_id, stage)}/{path.lstrip('/')}"


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(method, url, headers=None, *, verify=True, timeout_s=20):
    u = urllib.parse.urlsplit(url)
    conn = (HTTPSConnection(u.hostname, u.port or 443, timeout=timeout_s, context=_ssl_context(verify))
            if u.scheme == "https" else HTTPConnection(u.hostname, u.port or 80, timeout=timeout_s))
    try:
        conn.putrequest(method, (u.path or "/") + (f"?{u.query}" if u.query else ""))
        for name, value in (headers or {}).items():
            conn.putheader(name, value)
        conn.endheaders()
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


def _poll(url, headers, predicate, *, verify=True, timeout_s=150.0, interval_s=3.0,
          description="stage response"):
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        try:
            last = _http("GET", url, headers=headers, verify=verify)
        except OSError as exc:
            last = (None, {}, f"connection error: {exc!r}")
        else:
            if predicate(last[0], last[2]):
                return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: condition not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
