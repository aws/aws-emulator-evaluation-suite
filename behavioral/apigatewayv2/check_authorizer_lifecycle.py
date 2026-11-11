"""authorizer-lifecycle."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorizer-lifecycle"
GROUP = 'authorizers'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

def _create_http_api(ctx):
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api["ApiId"]))
    return api["ApiId"]

_AUTHORIZER_CODE = """
def lambda_handler(event, context):
    return {"isAuthorized": True, "context": {"src": "sim2real"}}
"""

def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-lambda-")
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
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=TAGS_KV,
    )["Role"]["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy)
    )

    def _cleanup_role():
        try:
            for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    return arn


def _create_lambda(ctx, handler_code):
    """Create a python Lambda; return {name, arn}. Registers teardown."""
    role_arn = _create_lambda_role(ctx)
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": 30,
        "MemorySize": 128,
        "Tags": dict(TAGS),
    }
    deadline = time.monotonic() + 40
    last_err = None
    arn = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            break
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    if arn is None:
        raise last_err or RuntimeError(f"failed to create lambda {name}")
    _deadline = time.monotonic() + 60
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            break
        if time.monotonic() >= _deadline:
            raise AssertionError(f"lambda {name} active not met within 60s")
        time.sleep(2.0)
    return {"name": name, "arn": arn}

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAuthorizer(JWT) -> GetAuthorizer reflects fields -> DeleteAuthorizer removes it."""
    agw = ctx.client("apigatewayv2")
    api_id = _create_http_api(ctx)
    name = ctx.unique_name("sim2real-behav-authz-")

    # A JWT authorizer requires a REAL, resolvable OpenID issuer (AWS validates the
    # /.well-known/openid-configuration discovery endpoint at create time), which a
    # placeholder Cognito pool does not have. Use a REQUEST (Lambda) authorizer -- the
    # control-plane lifecycle we are asserting, with no external dependency.
    fn = _create_lambda(ctx, _AUTHORIZER_CODE)
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{fn['arn']}/invocations"
    )
    created = agw.create_authorizer(
        ApiId=api_id,
        Name=name,
        AuthorizerType="REQUEST",
        AuthorizerUri=authorizer_uri,
        IdentitySource=["$request.header.Authorization"],
        AuthorizerPayloadFormatVersion="2.0",
        EnableSimpleResponses=True,
    )
    authorizer_id = created["AuthorizerId"]

    got = agw.get_authorizer(ApiId=api_id, AuthorizerId=authorizer_id)
    assert got["Name"] == name, f"authorizer name mismatch: {got.get('Name')}"
    assert got["AuthorizerType"] == "REQUEST", f"authorizer type mismatch: {got.get('AuthorizerType')}"

    agw.delete_authorizer(ApiId=api_id, AuthorizerId=authorizer_id)
    code, message = _error_code(
        lambda: agw.get_authorizer(ApiId=api_id, AuthorizerId=authorizer_id)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    expected_message = "Invalid Authorizer identifier specified"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises.
    Throttling is retried."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, error.get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )
    raise AssertionError("unreachable: the loop always returns or raises")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
