"""e2e-authorizer-protected-method-consequence."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-authorizer-protected-method-consequence"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestInvokeAuthorizer on a Lambda TOKEN authorizer returns an Allow policy for the valid
    token and Deny for an invalid one, while TestInvokeMethod reaches the MOCK integration
    regardless of identity source, because it does not enforce the authorizer."""
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-e2e-authz-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_ignore_missing(iam, role_name))

    code = (
        "def handler(event, context):\n"
        "    token = event.get('authorizationToken', '')\n"
        "    effect = 'Allow' if token == 'sim2real-allow-me' else 'Deny'\n"
        "    return {\n"
        "        'principalId': 'sim2real-user',\n"
        "        'policyDocument': {\n"
        "            'Version': '2012-10-17',\n"
        "            'Statement': [\n"
        "                {'Action': 'execute-api:Invoke', 'Effect': effect,"
        " 'Resource': event['methodArn']}\n"
        "            ],\n"
        "        },\n"
        "    }\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    zip_bytes = buf.getvalue()

    function_name = ctx.unique_name("sim2real-e2e-authz-fn-")
    function_arn = _create_function_with_retry(
        lam, function_name, role_arn, zip_bytes, tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: _delete_function_ignore_missing(lam, function_name))
    _wait_function_active(lam, function_name)

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-e2e-authz-api-"),
        tags={"sim2real": CHECK},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_ignore_missing(apigw, api_id))

    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{function_arn}/invocations"
    )
    authorizer = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-e2e-authorizer-"),
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )
    authorizer_id = authorizer["id"]

    source_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{api_id}/authorizers/{authorizer_id}"
    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-apigw-invoke",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=source_arn,
    )

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="secure")
    resource_id = resource["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "secure-ok"}'},
    )

    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment["id"])

    # Valid identity source -> Allow, wrong one -> Deny; the decision is the policy's Effect, while
    # clientStatus only reports whether the Lambda invocation succeeded. Permission propagation after
    # add_permission can lag, so the allow probe is polled to a deadline.
    allow_probe = _poll_authorizer_probe(
        apigw, api_id, authorizer_id, "sim2real-allow-me", timeout_s=90.0
    )
    assert allow_probe["clientStatus"] == 0, {
        "clientStatus": allow_probe.get("clientStatus"),
        "log": allow_probe.get("log"),
    }
    allow_effect = json.loads(allow_probe.get("policy") or "{}")["Statement"][0]["Effect"]
    assert allow_effect == "Allow", allow_effect

    deny_probe = apigw.test_invoke_authorizer(
        restApiId=api_id,
        authorizerId=authorizer_id,
        headers={"Authorization": "wrong-token"},
    )
    assert deny_probe["clientStatus"] == 0, deny_probe.get("clientStatus")
    deny_effect = json.loads(deny_probe.get("policy") or "{}")["Statement"][0]["Effect"]
    assert deny_effect == "Deny", deny_effect

    # TestInvokeMethod invokes the integration directly and does not enforce a CUSTOM authorizer's
    # decision: both a valid and an invalid identity source reach the MOCK integration and get 200.
    allowed = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        headers={"Authorization": "sim2real-allow-me"},
    )
    assert allowed["status"] == 200, allowed.get("status")
    assert "secure-ok" in allowed["body"], allowed.get("body")

    denied = apigw.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        headers={"Authorization": "wrong-token"},
    )
    assert denied["status"] == 200, (denied.get("status"), (denied.get("body") or "")[:200])
    assert "secure-ok" in denied["body"], denied.get("body")

    # A live authorizer cannot be deleted while it is still attached to a method (real AWS
    # returns ConflictException) -- detach it from the method first, exactly as a real client
    # would have to.
    apigw.update_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        patchOperations=[{"op": "replace", "path": "/authorizationType", "value": "NONE"}],
    )
    apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    not_found = ("NotFoundException", "Invalid Authorizer identifier specified")
    err_after = _error(
        lambda: apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    )
    assert err_after == not_found, f"expected {not_found!r} reading the deleted authorizer, got {err_after!r}"

    # A mutation against the deleted authorizer id must also fail, not just the read.
    update_err_after = _error(
        lambda: apigw.update_authorizer(
            restApiId=api_id,
            authorizerId=authorizer_id,
            patchOperations=[{"op": "replace", "path": "/name", "value": "sim2real-dead"}],
        )
    )
    assert update_err_after == not_found, (
        f"expected {not_found!r} mutating the deleted authorizer, got {update_err_after!r}"
    )


def _create_function_with_retry(lam, function_name, role_arn, zip_bytes, attempts=8, tags=None):
    last_exc = None
    for _ in range(attempts):
        try:
            return lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
                Tags=tags or {},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_exc = exc
            time.sleep(3.0)
    raise last_exc


def _wait_function_active(lam, function_name, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=function_name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"lambda function {function_name} never reached Active state")


def _poll_authorizer_probe(
    apigw, api_id, authorizer_id, token, timeout_s=60.0, interval_s=3.0
):
    """Poll until the authorizer Lambda invocation itself succeeds (clientStatus == 0);
    permission propagation can lag by a few seconds after add_permission."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = apigw.test_invoke_authorizer(
            restApiId=api_id,
            authorizerId=authorizer_id,
            headers={"Authorization": token},
        )
        if last["clientStatus"] == 0:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"authorizer invocation never reached clientStatus==0 within {timeout_s}s; "
        f"last saw clientStatus={last.get('clientStatus') if last else None} log={last.get('log') if last else None}"
    )


def _delete_role_ignore_missing(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_function_ignore_missing(lam, function_name: str) -> None:
    try:
        lam.delete_function(FunctionName=function_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_rest_api_ignore_missing(apigw, api_id: str) -> None:
    try:
        apigw.delete_rest_api(restApiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
