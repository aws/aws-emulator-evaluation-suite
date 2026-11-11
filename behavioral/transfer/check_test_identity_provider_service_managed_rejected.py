"""test-identity-provider-service-managed-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-identity-provider-service-managed-rejected"
GROUP = "server-side"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestIdentityProvider on a SERVICE_MANAGED server is InvalidRequestException and leaves the
    server unchanged, while an API_GATEWAY server accepts the same call with StatusCode 200."""
    transfer = ctx.client("transfer")

    managed_server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="SERVICE_MANAGED",
        Domain="S3",
        EndpointType="PUBLIC",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-sm-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=managed_server_id))

    code, message = _error(
        lambda: transfer.test_identity_provider(ServerId=managed_server_id, UserName="anyuser")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == f"{managed_server_id} not configured for external auth", (
        f"unexpected InvalidRequestException message {message!r}"
    )

    # The rejected call leaves the identity provider configuration untouched.
    described = transfer.describe_server(ServerId=managed_server_id)["Server"]
    assert described["IdentityProviderType"] == "SERVICE_MANAGED", (
        f"expected the rejected call to leave IdentityProviderType untouched, "
        f"got {described.get('IdentityProviderType')!r}"
    )

    # Positive control: the rejection above is type-specific, not a blanket failure.
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    mock_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-idp-mock-role"
    invoke_url, rest_api_id = _create_mock_idp_api(ctx, mock_role_arn)
    role_arn = _create_invocation_role(ctx, rest_api_id)


    gateway_server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="API_GATEWAY",
        Domain="S3",
        EndpointType="PUBLIC",
        IdentityProviderDetails={"Url": invoke_url, "InvocationRole": role_arn},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-gw-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=gateway_server_id))

    # The new invocation role takes time to propagate in IAM; until then the call returns a
    # non-200 StatusCode rather than raising.
    response = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        response = transfer.test_identity_provider(ServerId=gateway_server_id, UserName="anyuser")
        if response["StatusCode"] == 200:
            break
        time.sleep(3)

    assert response is not None, "test_identity_provider never returned a response"
    assert response["StatusCode"] == 200, f"expected StatusCode 200, got {response}"


def _error(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_mock_idp_api(ctx, mock_role_arn: str):
    api = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-transfer-idp-neg-api-")
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
            "HomeDirectory": "/sim2real-idp-neg-test",
        }
    )
    api.put_integration_response(
        restApiId=rest_api_id,
        resourceId=proxy_id,
        httpMethod="ANY",
        statusCode="200",
        responseTemplates={
            "application/json": response_body,
        },
    )

    api.create_deployment(restApiId=rest_api_id, stageName="test")
    invoke_url = ctx.rest_api_url(rest_api_id, 'test')
    return invoke_url, rest_api_id


def _create_invocation_role(ctx, rest_api_id: str) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-transfer-idp-neg-role-")
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
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "execute-api:Invoke", "Resource": api_arn}]}
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



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
