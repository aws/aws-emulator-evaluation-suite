"""test-identity-provider-invokes-configured-endpoint."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "test-identity-provider-invokes-configured-endpoint"
GROUP = "server-side"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestIdentityProvider on an API_GATEWAY server invokes the configured endpoint and returns StatusCode 200 with a
    response that carries the unique marker the endpoint put in HomeDirectory."""
    transfer = ctx.client("transfer")
    sts = ctx.client("sts")
    marker = f"sim2real-marker-{uuid.uuid4().hex}"
    account_id = sts.get_caller_identity()["Account"]
    # Transfer validates that the "Role" field in the IdP response is a syntactically valid
    # IAM role ARN in the caller's account before it will surface the raw response body -- so the
    # mock's canned response must use a real-looking role ARN in the caller's own account
    # (it does not need to be assumable for this check; only the account+ARN shape matters).
    mock_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-idp-mock-role"

    invoke_url, rest_api_id = _create_mock_idp_api(ctx, marker, mock_role_arn)
    role_arn = _create_invocation_role(ctx, rest_api_id)


    server_id = transfer.create_server(
        Protocols=["SFTP"],
        IdentityProviderType="API_GATEWAY",
        EndpointType="PUBLIC",
        Domain="S3",
        IdentityProviderDetails={"Url": invoke_url, "InvocationRole": role_arn},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-idp-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    # The invocation role's trust/invoke policy is IAM-eventually-consistent: real AWS answers
    # with StatusCode 200 and an empty Response well before the role is assumable, surfacing the
    # propagation failure only in Message ("Unable to assume role ... STS: 403"). So the retry
    # target is the real success signal -- the marker actually present in the response body --
    # not the StatusCode alone.
    described = None
    deadline_s = 60
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        described = transfer.test_identity_provider(
            ServerId=server_id, UserName="sim2realuser", UserPassword="does-not-matter", ServerProtocol="SFTP"
        )
        if described["StatusCode"] == 200 and marker in described.get("Response", ""):
            break
        time.sleep(3)

    assert described is not None, f"test_identity_provider never returned within the {deadline_s}s deadline"
    resp_text = described.get("Response", "")
    assert described["StatusCode"] == 200, f"expected StatusCode 200, got {described}"
    assert marker in resp_text, (
        f"TestIdentityProvider did not surface the real endpoint response body: {resp_text!r} "
        f"msg={described.get('Message', '')!r}"
    )


def _create_mock_idp_api(ctx, marker: str, mock_role_arn: str):
    api = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-transfer-idp-api-")
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
            "HomeDirectory": f"/sim2real-idp-test/{marker}",
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
    name = ctx.unique_name("sim2real-transfer-idp-role-")
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
