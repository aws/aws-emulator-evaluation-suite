"""authorizer-cache-ttl-window."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "authorizer-cache-ttl-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """authorizerResultTtlInSeconds is stored/retrievable, TestInvokeAuthorizer really
    invokes the backing Lambda and echoes back its Allow/Deny decision, and
    UpdateAuthorizer can change the configured TTL window."""
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    region = ctx.region

    authz_fn = _create_lambda_authorizer(ctx)

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    authorizer_uri = (
        f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/"
        f"{authz_fn['function_arn']}/invocations"
    )
    authorizer = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authz-"),
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=300,
    )
    authorizer_id = authorizer["id"]
    assert authorizer["authorizerResultTtlInSeconds"] == 300, "initial TTL not stored as configured"

    lam.add_permission(
        FunctionName=authz_fn["function_name"],
        StatementId="apigw-invoke-authorizer",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=(
            f"arn:aws:execute-api:{region}:{authz_fn['account_id']}:"
            f"{api_id}/authorizers/{authorizer_id}"
        ),
    )

    # Positive: a valid token flows through to the Lambda and its Allow decision
    # is echoed back verbatim by TestInvokeAuthorizer.
    allow_resp = _test_invoke_with_retry(
        apigw, api_id, authorizer_id, {"Authorization": "good-token"}
    )
    assert allow_resp["principalId"] == "user-1", (
        f"expected the Lambda's principalId 'user-1' to be echoed back, got {allow_resp.get('principalId')!r}"
    )
    allow_policy = json.loads(allow_resp["policy"])
    assert allow_policy["Statement"][0]["Effect"] == "Allow", f"expected an Allow policy, got {allow_policy}"
    assert allow_resp["clientStatus"] == 0, (
        f"expected clientStatus 0 (the authorizer Lambda itself executed successfully), "
        f"got {allow_resp['clientStatus']!r}"
    )

    # Negative: an invalid token causes the same Lambda to return Deny. clientStatus
    # reflects whether the LAMBDA INVOCATION itself succeeded, not the Allow/Deny
    # decision -- a successful Deny reports clientStatus 0 too, same as Allow above.
    # The decision is only visible in the policy.
    deny_resp = _test_invoke_with_retry(
        apigw, api_id, authorizer_id, {"Authorization": "bad-token"}
    )
    deny_policy = json.loads(deny_resp["policy"])
    assert deny_policy["Statement"][0]["Effect"] == "Deny", f"expected a Deny policy, got {deny_policy}"
    assert deny_resp["clientStatus"] == 0, (
        f"expected clientStatus 0 (the Lambda executed successfully and returned Deny, "
        f"not an invocation failure), got {deny_resp['clientStatus']!r}"
    )

    # UpdateAuthorizer can shrink the TTL window to 0 (effectively disabling caching)
    # and GetAuthorizer reflects the new value exactly.
    updated = apigw.update_authorizer(
        restApiId=api_id,
        authorizerId=authorizer_id,
        patchOperations=[{"op": "replace", "path": "/authorizerResultTtlInSeconds", "value": "0"}],
    )
    assert updated["authorizerResultTtlInSeconds"] == 0, (
        f"expected UpdateAuthorizer's own response to reflect the shrunk TTL, "
        f"got {updated.get('authorizerResultTtlInSeconds')!r}"
    )

    refetched = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert refetched["authorizerResultTtlInSeconds"] == 0, "UpdateAuthorizer TTL change not persisted"


def _lambda_zip_bytes() -> bytes:
    code = (
        "def handler(event, context):\n"
        "    token = event.get('authorizationToken', '')\n"
        "    effect = 'Allow' if token == 'good-token' else 'Deny'\n"
        "    return {\n"
        "        'principalId': 'user-1',\n"
        "        'policyDocument': {\n"
        "            'Version': '2012-10-17',\n"
        "            'Statement': [{\n"
        "                'Action': 'execute-api:Invoke',\n"
        "                'Effect': effect,\n"
        "                'Resource': event.get('methodArn', '*'),\n"
        "            }],\n"
        "        },\n"
        "    }\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_authorizer(ctx) -> dict[str, Any]:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")

    role_name = ctx.unique_name("sim2real-apigw-authz-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    fn_name = ctx.unique_name("sim2real-apigw-authz-fn-")
    zip_bytes = _lambda_zip_bytes()
    fn_arn = None
    last_err: Exception | None = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            fn_arn = resp["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if fn_arn is None:
        raise AssertionError(f"lambda function never became creatable (IAM propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    account_id = sts.get_caller_identity()["Account"]
    return {"function_name": fn_name, "function_arn": fn_arn, "account_id": account_id}


def _test_invoke_with_retry(apigw, api_id: str, authorizer_id: str, headers: dict[str, str]) -> dict[str, Any]:
    """The Lambda's execution role/permission can take a moment to propagate; retry
    on the transient failure mode where the authorizer invocation itself errors."""
    last_exc: Exception | None = None
    for _ in range(8):
        resp = apigw.test_invoke_authorizer(
            restApiId=api_id,
            authorizerId=authorizer_id,
            headers=headers,
            pathWithQueryString="/anything",
        )
        if resp.get("policy"):
            return resp
        last_exc = AssertionError(f"no policy returned, log={resp.get('log')}")
        time.sleep(2)
    raise last_exc or AssertionError("test_invoke_authorizer never returned a policy")


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
