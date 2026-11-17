"""create-authorizer-ttl-out-of-range-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-authorizer-ttl-out-of-range-rejected"
GROUP = "authorizers"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

_AUTHORIZER_CODE = """
def lambda_handler(event, context):
    return {"isAuthorized": True, "context": {"src": "sim2real"}}
"""


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-authzttl-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/", Tags=TAGS_KV
    )["Role"]["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))

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
    role_arn = _create_lambda_role(ctx)
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-authzttl-")
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
    deadline = time.monotonic() + 60
    while True:
        state = lam.get_function_configuration(FunctionName=name).get("State")
        if state == "Active":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"lambda {name} active not met within 60s")
        time.sleep(2.0)
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAuthorizer with AuthorizerResultTtlInSeconds above the documented 3600 s ceiling is
    rejected BadRequestException and creates no authorizer; 3600 itself, the ceiling value, is
    accepted."""
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(Name=ctx.unique_name("sim2real-behav-authzttl-"), ProtocolType="HTTP", Tags=TAGS)
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    function_arn = _create_lambda(ctx, _AUTHORIZER_CODE)
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{function_arn}/invocations"
    )

    before = agw.get_authorizers(ApiId=api_id).get("Items", [])

    code, message = _error(
        lambda: agw.create_authorizer(
            ApiId=api_id,
            Name=ctx.unique_name("sim2real-behav-authz-badttl-"),
            AuthorizerType="REQUEST",
            AuthorizerUri=authorizer_uri,
            IdentitySource=["$request.header.Authorization"],
            AuthorizerPayloadFormatVersion="2.0",
            AuthorizerResultTtlInSeconds=3601,
        )
    )
    assert code == "BadRequestException", (
        f"CreateAuthorizer with ttl 3601: expected BadRequestException, got {code}: {message!r}"
    )
    expected_message = "Authorizer result TTL outside allowable range. TTL must be between 0 and 3600 seconds."
    assert message == expected_message, (
        f"CreateAuthorizer with ttl 3601: unexpected message {message!r}"
    )

    # effect absent: the rejected call minted no authorizer.
    after_reject = agw.get_authorizers(ApiId=api_id).get("Items", [])
    assert len(after_reject) == len(before), (
        f"the rejected CreateAuthorizer changed the authorizer count: "
        f"before={len(before)} after={len(after_reject)}"
    )

    # positive control: the ceiling value 3600 is accepted.
    created = agw.create_authorizer(
        ApiId=api_id,
        Name=ctx.unique_name("sim2real-behav-authz-okttl-"),
        AuthorizerType="REQUEST",
        AuthorizerUri=authorizer_uri,
        IdentitySource=["$request.header.Authorization"],
        AuthorizerPayloadFormatVersion="2.0",
        AuthorizerResultTtlInSeconds=3600,
    )
    authorizer_id = created["AuthorizerId"]
    ctx.on_cleanup(lambda: agw.delete_authorizer(ApiId=api_id, AuthorizerId=authorizer_id))
    got = agw.get_authorizer(ApiId=api_id, AuthorizerId=authorizer_id)
    assert got.get("AuthorizerResultTtlInSeconds") == 3600, (
        f"the accepted ceiling ttl did not round-trip: {got.get('AuthorizerResultTtlInSeconds')!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
