"""authorizer-protected-method-invoke-flow."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorizer-protected-method-invoke-flow"
GROUP = "e2e"
SERVICES = ["apigateway"]

_AUTHORIZER_CODE = """
def handler(event, context):
    token = event.get("authorizationToken", "")
    effect = "Allow" if token == "allow-me" else "Deny"
    return {
        "principalId": "sim2real-test-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": event.get("methodArn", "*"),
                }
            ],
        },
    }
"""


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A TOKEN Lambda authorizer's Allow/Deny decision shows in TestInvokeAuthorizer, and at the deployed
    stage the denied token is refused 403 with the explicit-deny message while the allowed token
    reaches the MOCK integration with 200."""
    iam = ctx.client("iam")
    lambda_client = ctx.client("lambda")
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-authz-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    fn_name = ctx.unique_name("sim2real-authz-fn-")
    zip_bytes = _lambda_zip(_AUTHORIZER_CODE)
    lambda_arn = _create_function_with_retry(
        lambda_client,
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=10,
    )["FunctionArn"]
    ctx.on_cleanup(lambda: lambda_client.delete_function(FunctionName=fn_name))
    _wait_lambda_active(lambda_client, fn_name)

    rest_api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-authz-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    authorizer_id = apigw.create_authorizer(
        restApiId=rest_api_id,
        name=ctx.unique_name("sim2real-authorizer-"),
        type="TOKEN",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations"
        ),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )["id"]

    lambda_client.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{account_id}:{rest_api_id}/authorizers/{authorizer_id}",
    )

    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(
        restApiId=rest_api_id, parentId=root_id, pathPart="secure"
    )["id"]
    apigw.put_method(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="",
    )
    apigw.create_deployment(restApiId=rest_api_id, stageName="test")

    # TestInvokeAuthorizer's `clientStatus` field is 0 whenever the Lambda authorizer
    # *executed* successfully (returned a well-formed policy) — it is NOT the Allow/Deny
    # verdict. The verdict lives in the `policy` field's IAM policy document, so the real
    # Allow-vs-Deny decision must be read from there.
    try:
        denied = apigw.test_invoke_authorizer(
            restApiId=rest_api_id, authorizerId=authorizer_id, headers={"Authorization": "deny-me"}
        )
    except ClientError as exc:
        raise AssertionError(
            f"expected a completed (denied) authorizer test invocation, got ClientError {exc.response['Error']['Code']}"
        )
    assert denied.get("clientStatus") == 0, f"expected the authorizer function itself to execute cleanly, got clientStatus={denied.get('clientStatus')}"
    denied_effect = json.loads(denied["policy"])["Statement"][0]["Effect"]
    assert denied_effect == "Deny", f"expected Effect=Deny for an invalid token, got {denied_effect!r}"

    allowed = apigw.test_invoke_authorizer(
        restApiId=rest_api_id, authorizerId=authorizer_id, headers={"Authorization": "allow-me"}
    )
    assert allowed.get("clientStatus") == 0, f"expected clientStatus=0 (allowed) for a valid token, got {allowed.get('clientStatus')}"
    allowed_effect = json.loads(allowed["policy"])["Statement"][0]["Effect"]
    assert allowed_effect == "Allow", f"expected Effect=Allow for a valid token, got {allowed_effect!r}"
    assert allowed.get("principalId") == "sim2real-test-user", (
        f"expected the authorizer's principalId to flow through, got {allowed.get('principalId')!r}"
    )

    # TestInvokeAuthorizer only simulates the decision; the deployed stage shows whether the method
    # enforces it (TestInvokeMethod does not enforce a CUSTOM authorizer's decision).
    invoke_url = f"{ctx.rest_api_url(rest_api_id, 'test')}/secure"

    denied_status, denied_body = _poll_invoke(
        invoke_url, {"Authorization": "deny-me"}, timeout_s=_budget_s(ctx, 60.0),
        done=lambda s, b: s == 403 and _json(b) == _DENY_BODY,
    )
    assert denied_status == 403, (
        f"expected the real invoke endpoint to reject a denied token, got status={denied_status}"
    )
    assert _json(denied_body) == _DENY_BODY, f"unexpected explicit-deny body {denied_body!r}"

    allowed_status, _ = _poll_invoke(
        invoke_url, {"Authorization": "allow-me"}, timeout_s=_budget_s(ctx, 60.0), done=lambda s, b: s == 200
    )
    assert allowed_status == 200, f"expected 200 invoking the protected method with an allowed token, got {allowed_status}"


_DENY_BODY = {
    "Message": "User is not authorized to access this resource with an explicit deny in an identity-based policy"
}


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _json(body: bytes):
    """The parsed JSON body, or None when it is not JSON."""
    try:
        return json.loads(body)
    except ValueError:
        return None


def _poll_invoke(url: str, headers: dict, timeout_s: float, done):
    """Poll the invoke endpoint every 2 s until done(status, body) or the deadline: deployment and
    authorizer propagation can answer other statuses first."""
    deadline = time.monotonic() + timeout_s
    last_status, last_body = None, b""
    while True:
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                last_status, last_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            last_status, last_body = exc.code, exc.read()
        except urllib.error.URLError:
            last_status, last_body = None, b""
        if done(last_status, last_body) or time.monotonic() >= deadline:
            return last_status, last_body
        time.sleep(2.0)


def _lambda_zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_function_with_retry(lambda_client, retries: int = 12, delay_s: float = 5.0, **kwargs):
    last_err = None
    for _ in range(retries):
        try:
            return lambda_client.create_function(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_err = exc
            time.sleep(delay_s)
    raise last_err


def _wait_lambda_active(lambda_client, function_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        state = lambda_client.get_function(FunctionName=function_name)["Configuration"]["State"]
        if state == "Active":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"Lambda function never became Active, last state={state!r}")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
