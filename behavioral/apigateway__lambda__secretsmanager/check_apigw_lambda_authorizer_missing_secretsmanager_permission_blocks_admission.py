"""apigw-lambda-authorizer-missing-secretsmanager-permission-blocks-admission."""
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

CHECK = "apigw-lambda-authorizer-missing-secretsmanager-permission-blocks-admission"
GROUP = "authorizers"
SERVICES = ["apigateway", "iam", "lambda", "secretsmanager"]

_PREFIX = "sim2real-xsvc-"
_POLICY_NAME = "secret-read"

_AUTHORIZER_CODE = """
import boto3

_client = boto3.client("secretsmanager")


def handler(event, context):
    secret_id = event["stageVariables"]["secretId"]
    _client.get_secret_value(SecretId=secret_id)
    return {
        "principalId": "sim2real-authz-user",
        "policyDocument": {"Version": "2012-10-17", "Statement": [{
            "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": event["methodArn"]}]},
    }
"""


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A REST authorizer whose execution role lacks secretsmanager:GetSecretValue cannot admit
    any call: it fails at the secret read with the authorizer-configuration error, and the
    identical request is admitted again once that one permission is restored.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html
    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_evaluation-logic.html
    """
    secret_arn = _create_secret(ctx)
    iam = ctx.client("iam")
    role_name, fn = _create_authorizer_fn(ctx, secret_arn)
    api_id, _root_id, _authorizer_id = _wire_api(ctx, fn, secret_arn)

    url = _rest_invoke_url(ctx, api_id, "live", "/secure")

    status, _h, text = _poll(url, lambda s, t: s == 200, verify=ctx.http_verify,
                             description="GET /secure while the role can read the secret")
    assert status == 200 and text == '{"served":true}', (
        f"the positive control (role holds the permission) must be admitted, got "
        f"{status}: {text[:300]!r}")

    iam.delete_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME)

    status, headers, text = _poll(
        url, lambda s, t: s == 500, verify=ctx.http_verify,
        description="GET /secure once the role's secretsmanager:GetSecretValue is revoked")
    assert status == 500, (
        f"a role that can no longer read the secret must never admit the call, got "
        f"{status}: {text[:300]!r}")
    assert text == '{"message":null}', (
        f'expected the default authorizer-configuration-error body \'{{"message":null}}\', '
        f"got {text[:300]!r}")
    assert headers.get("x-amzn-errortype") == "AuthorizerConfigurationException", (
        f"expected x-amzn-ErrorType AuthorizerConfigurationException, got "
        f"{headers.get('x-amzn-errortype')!r}")

    iam.put_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}]}))

    status, _h, text = _poll(url, lambda s, t: s == 200, verify=ctx.http_verify,
                             description="GET /secure once the permission is restored")
    assert status == 200 and text == '{"served":true}', (
        f"restoring the one permission removed must admit the identical call again, got "
        f"{status}: {text[:300]!r}")


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
    resp = sm.create_secret(Name=name, SecretString=f"sim2real{_unique_token(24)}",
                            Tags=[{"Key": k, "Value": v} for k, v in _xtags().items()])
    arn = resp["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


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
    iam.put_role_policy(RoleName=role_name, PolicyName="logs", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [
            "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*"}]}))
    iam.put_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}]}))

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
    return role_name, {"name": name, "arn": arn}


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


def _poll(url, predicate, *, verify=True, timeout_s=180.0, interval_s=4.0,
          description="stage response"):
    deadline = time.monotonic() + timeout_s
    last = (None, {}, "")
    while True:
        try:
            last = _http("GET", url, headers={"x-app-key": "whatever"}, verify=verify)
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
