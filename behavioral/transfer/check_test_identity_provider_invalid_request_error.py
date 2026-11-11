"""test-identity-provider-invalid-request-error."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "test-identity-provider-invalid-request-error"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestIdentityProvider on a SERVICE_MANAGED server is InvalidRequestException, distinct from
    ResourceNotFoundException for a missing server; an API_GATEWAY server accepts the same call."""
    transfer = ctx.client("transfer")

    server_id = transfer.create_server(
        IdentityProviderType="SERVICE_MANAGED",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-invreq-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    user_name = ctx.unique_name("sim2real-behav-user-").replace("-", "_")
    role_arn = f"arn:aws:iam::{_account_id(ctx)}:role/does-not-need-to-exist-for-this-call"
    transfer.create_user(ServerId=server_id, UserName=user_name, Role=role_arn)
    ctx.on_cleanup(lambda: transfer.delete_user(ServerId=server_id, UserName=user_name))

    # The server genuinely exists (isolates the failure to identity-provider type, not a bad id).
    described = transfer.describe_server(ServerId=server_id)["Server"]
    assert described["IdentityProviderType"] == "SERVICE_MANAGED", (
        f"expected freshly created server to report SERVICE_MANAGED, got "
        f"{described['IdentityProviderType']!r}"
    )

    invalid_code, invalid_message = _error(
        lambda: transfer.test_identity_provider(ServerId=server_id, UserName=user_name)
    )
    assert invalid_code == "InvalidRequestException", (
        f"expected InvalidRequestException for SERVICE_MANAGED server, got {invalid_code}"
    )
    assert invalid_message == f"{server_id} not configured for external auth", (
        f"unexpected InvalidRequestException message {invalid_message!r}"
    )

    missing_server_id = "s-00000000000000000"
    not_found_code, not_found_message = _error(
        lambda: transfer.test_identity_provider(ServerId=missing_server_id, UserName=user_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for missing server, got {not_found_code}"
    )
    assert not_found_message == "Unknown server", (
        f"unexpected ResourceNotFoundException message {not_found_message!r}"
    )

    assert invalid_code != not_found_code, (
        f"type-mismatch and missing-server rejections must carry distinct codes, "
        f"both were {invalid_code!r}"
    )

    # Positive control: the rejection above is type-specific, not a blanket failure.
    account_id = _account_id(ctx)
    mock_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-idp-mock-role"
    invoke_url, rest_api_id = _create_mock_idp_api(ctx, mock_role_arn)
    invocation_role_arn = _create_invocation_role(ctx, rest_api_id)

    gateway_server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="API_GATEWAY",
        Domain="S3",
        EndpointType="PUBLIC",
        IdentityProviderDetails={"Url": invoke_url, "InvocationRole": invocation_role_arn},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-invreq-gw-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=gateway_server_id))

    # The new invocation role takes time to propagate in IAM; until then Transfer returns 200
    # wrapping a non-200 StatusCode rather than raising, so the retry inspects the body.
    positive_response = _poll_until_ready(
        lambda: transfer.test_identity_provider(ServerId=gateway_server_id, UserName=user_name),
        is_ready=lambda resp: resp.get("StatusCode") == 200,
        timeout_s=60,
    )
    assert positive_response.get("StatusCode") == 200, (
        f"expected the API_GATEWAY-backed server to accept TestIdentityProvider, "
        f"got {positive_response}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected this TestIdentityProvider call to be rejected, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_mock_idp_api(ctx, mock_role_arn: str):
    api = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-transfer-invreq-api-")
    rest_api_id = api.create_rest_api(name=name)["id"]
    ctx.on_cleanup(lambda: api.delete_rest_api(restApiId=rest_api_id))

    root_id = next(r["id"] for r in api.get_resources(restApiId=rest_api_id)["items"] if r["path"] == "/")
    proxy_id = api.create_resource(restApiId=rest_api_id, parentId=root_id, pathPart="{proxy+}")["id"]

    api.put_method(
        restApiId=rest_api_id,
        resourceId=proxy_id,
        httpMethod="ANY",
        authorizationType="AWS_IAM",
        requestParameters={"method.request.path.proxy": True},
    )
    api.put_integration(
        restApiId=rest_api_id,
        resourceId=proxy_id,
        httpMethod="ANY",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
        passthroughBehavior="WHEN_NO_MATCH",
    )
    api.put_method_response(
        restApiId=rest_api_id, resourceId=proxy_id, httpMethod="ANY", statusCode="200",
    )
    response_body = json.dumps(
        {
            "Role": mock_role_arn,
            "HomeDirectory": "/sim2real-invreq-test",
        }
    )
    api.put_integration_response(
        restApiId=rest_api_id,
        resourceId=proxy_id,
        httpMethod="ANY",
        statusCode="200",
        responseTemplates={"application/json": response_body},
    )

    api.create_deployment(restApiId=rest_api_id, stageName="test")
    invoke_url = ctx.rest_api_url(rest_api_id, 'test')
    return invoke_url, rest_api_id


def _create_invocation_role(ctx, rest_api_id: str) -> str:
    iam = ctx.client("iam")
    account_id = _account_id(ctx)
    name = ctx.unique_name("sim2real-transfer-invreq-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    api_arn = f"arn:aws:execute-api:{ctx.region}:{account_id}:{rest_api_id}/*/*/*"
    iam.put_role_policy(
        RoleName=name,
        PolicyName="invoke-api",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "execute-api:Invoke", "Resource": api_arn}
                ],
            }
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="invoke-api")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return arn


def _poll_until_ready(fn, *, is_ready, timeout_s: float):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            last = exc
        else:
            if is_ready(last):
                return last
        time.sleep(3)
    raise AssertionError(
        f"call never became ready within {timeout_s}s (IAM role propagation); last saw {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
