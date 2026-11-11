"""test-invoke-authorizer-request-type-header-allow-and-deny."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-invoke-authorizer-request-type-header-allow-and-deny"
GROUP = "server-side"
SERVICES = ["apigateway"]

_IDENTITY_HEADER = "X-Sim2real-Role"
_ALLOWED_VALUE = "admin"

_HANDLER = """
def handler(event, context):
    headers = event.get("headers") or {}
    role = headers.get("%s", "")
    effect = "Allow" if role == "%s" else "Deny"
    return {
        "principalId": "sim2real-request-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": event.get("methodArn", "*")}
            ],
        },
    }
""" % (_IDENTITY_HEADER, _ALLOWED_VALUE)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0):
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
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _create_lambda(ctx, handler_code):
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-behav-role-reqauthz-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="logs",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:*:*:*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs"), "NoSuchEntity")
    )

    fn_name = ctx.unique_name("sim2real-behav-fn-reqauthz-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{fn_name}"))

    kwargs = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": buf.getvalue()},
        Timeout=10,
        Tags={"sim2real": CHECK},
    )
    deadline = time.monotonic() + 90.0
    created = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            created = lam.create_function(**kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("InvalidParameterValueException",):
                last_err = exc
                time.sleep(2.0)
                continue
            raise
    if created is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name), "ResourceNotFoundException"))

    lam.get_waiter("function_active_v2").wait(
        FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    return {"name": fn_name, "arn": created["FunctionArn"]}


def _test_invoke_with_retry(apigw, api_id, authorizer_id, headers, timeout_s=60.0):
    """TestInvokeAuthorizer, retried while apigateway's Lambda-invoke permission propagates."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return apigw.test_invoke_authorizer(
                restApiId=api_id, authorizerId=authorizer_id, headers=headers
            )
        except apigw.exceptions.BadRequestException as exc:
            last_exc = exc
            time.sleep(2.0)
    raise AssertionError(f"test_invoke_authorizer never succeeded: {last_exc}")


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A REQUEST authorizer's header value reaches its Lambda, which allows or denies by it, and a
    request without the identity-source header answers clientStatus 401 without invoking it.
    """
    apigw = ctx.client("apigateway")
    fn = _create_lambda(ctx, _HANDLER)

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-reqauthz-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(_teardown(lambda: apigw.delete_rest_api(restApiId=api_id), "NotFoundException"))

    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-behav-authorizer-"),
        type="REQUEST",
        authorizerUri=(
            f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn['arn']}/invocations"
        ),
        identitySource=f"method.request.header.{_IDENTITY_HEADER}",
        authorizerResultTtlInSeconds=300,
    )["id"]

    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId="apigw-invoke-authorizer",
        Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{ctx.account}:{api_id}/authorizers/{authorizer_id}",
    )

    # Positive control: the header that carries the allowed value is let through.
    allow_resp = _test_invoke_with_retry(
        apigw, api_id, authorizer_id, headers={_IDENTITY_HEADER: _ALLOWED_VALUE}
    )
    assert allow_resp["clientStatus"] == 0, (
        f"the authorizer invocation with the allowed header value must succeed, got {allow_resp!r}"
    )
    allow_policy = json.loads(allow_resp["policy"])
    assert allow_policy["Statement"][0]["Effect"] == "Allow", (
        f"expected Effect=Allow for header value {_ALLOWED_VALUE!r}, got {allow_policy!r}"
    )

    # The same header with a value the Lambda does not allow: the function's own Deny is relayed.
    deny_resp = _test_invoke_with_retry(
        apigw, api_id, authorizer_id, headers={_IDENTITY_HEADER: "guest"}
    )
    assert deny_resp["clientStatus"] == 0, (
        f"the authorizer invocation with a disallowed header value must still run (not be "
        f"rejected client-side), got {deny_resp!r}"
    )
    deny_policy = json.loads(deny_resp["policy"])
    assert deny_policy["Statement"][0]["Effect"] == "Deny", (
        f"expected Effect=Deny for a header value the Lambda does not allow, got {deny_policy!r}"
    )
    assert deny_resp["principalId"] == allow_resp["principalId"] == "sim2real-request-user", (
        f"both invocations must surface the Lambda-computed principalId unchanged: "
        f"allow={allow_resp.get('principalId')!r} deny={deny_resp.get('principalId')!r}"
    )

    # API Gateway's own refusal: without the identity-source header the function is never invoked.
    missing_resp = apigw.test_invoke_authorizer(restApiId=api_id, authorizerId=authorizer_id, headers={})
    assert missing_resp["clientStatus"] == 401, (
        f"expected clientStatus 401 without the {_IDENTITY_HEADER} header, got {missing_resp!r}"
    )
    assert not missing_resp.get("policy") and not missing_resp.get("principalId"), (
        f"no policy or principalId may come back when the function is never invoked: {missing_resp!r}"
    )
    assert fn["name"] not in missing_resp.get("log", ""), (
        f"the log must not reference the authorizer function: {missing_resp.get('log')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
