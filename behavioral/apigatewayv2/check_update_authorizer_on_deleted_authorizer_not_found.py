"""update-authorizer-on-deleted-authorizer-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-authorizer-on-deleted-authorizer-not-found"
GROUP = "authorizers"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


def _create_http_api(ctx):
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api["ApiId"]))
    return api["ApiId"]


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


_AUTHORIZER_CODE = """
def lambda_handler(event, context):
    return {"isAuthorized": True, "context": {"src": "sim2real"}}
"""


def _create_lambda(ctx, handler_code):
    """Create a python Lambda; return {name, arn}. Registers teardown."""
    import io
    import zipfile

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
    deadline = time.monotonic() + 60
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


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAuthorizer on an AuthorizerId that DeleteAuthorizer already removed fails
    NotFoundException, while the same update against a sibling authorizer still succeeds."""
    agw = ctx.client("apigatewayv2")
    api_id = _create_http_api(ctx)
    fn = _create_lambda(ctx, _AUTHORIZER_CODE)
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"{fn['arn']}/invocations"
    )

    dead_id = agw.create_authorizer(
        ApiId=api_id,
        Name=ctx.unique_name("sim2real-behav-authz-dead-"),
        AuthorizerType="REQUEST",
        AuthorizerUri=authorizer_uri,
        IdentitySource=["$request.header.Authorization"],
        AuthorizerPayloadFormatVersion="2.0",
        EnableSimpleResponses=True,
    )["AuthorizerId"]
    agw.delete_authorizer(ApiId=api_id, AuthorizerId=dead_id)

    code, message = _error(
        lambda: agw.update_authorizer(ApiId=api_id, AuthorizerId=dead_id, Name="renamed-dead")
    )
    assert code == "NotFoundException", (
        f"UpdateAuthorizer on a deleted AuthorizerId: expected NotFoundException, "
        f"got {code}: {message!r}"
    )
    expected = "Invalid Authorizer identifier specified"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the dead id is still not retrievable; the refused update created nothing.
    absent_code, absent_message = _error(
        lambda: agw.get_authorizer(ApiId=api_id, AuthorizerId=dead_id)
    )
    assert absent_code == "NotFoundException", (
        f"GetAuthorizer on the dead id: expected NotFoundException, got {absent_code}: "
        f"{absent_message!r}"
    )

    # A live sibling authorizer is a legal neighbour: the same UpdateAuthorizer shape succeeds.
    control_id = agw.create_authorizer(
        ApiId=api_id,
        Name=ctx.unique_name("sim2real-behav-authz-live-"),
        AuthorizerType="REQUEST",
        AuthorizerUri=authorizer_uri,
        IdentitySource=["$request.header.Authorization"],
        AuthorizerPayloadFormatVersion="2.0",
        EnableSimpleResponses=True,
    )["AuthorizerId"]
    ctx.on_cleanup(lambda: agw.delete_authorizer(ApiId=api_id, AuthorizerId=control_id))
    updated = agw.update_authorizer(ApiId=api_id, AuthorizerId=control_id, Name="renamed-live")
    assert updated.get("Name") == "renamed-live", (
        f"the control update on a live authorizer did not apply: {updated!r}"
    )
    got_control = agw.get_authorizer(ApiId=api_id, AuthorizerId=control_id)
    assert got_control.get("Name") == "renamed-live", (
        f"independent read did not reflect the control update: {got_control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
