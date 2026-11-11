"""create-access-duplicate-external-id-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-access-duplicate-external-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["transfer"]

CREATE_REFUSAL = (
    "InvalidRequestException", "Cannot create access on server with IdP type: API_GATEWAY")
DESCRIBE_REFUSAL = (
    "InvalidRequestException", "Cannot describe access on server with IdP type: API_GATEWAY")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAccess on an API_GATEWAY IdP server fails InvalidRequestException with the IdP-type
    message for any Role/ExternalId and on retry; DescribeAccess is refused the same way.
    """
    transfer = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)
    server_id = _create_api_gateway_idp_server(ctx)
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    # Positive control: the server is reachable through an independent read.
    described_server = transfer.describe_server(ServerId=server_id)["Server"]
    assert described_server["IdentityProviderType"] == "API_GATEWAY", described_server[
        "IdentityProviderType"
    ]

    external_id = "S-1-5-21-111111111-222222222-333333333-1001"
    error = _client_error(
        lambda: transfer.create_access(ServerId=server_id, ExternalId=external_id, Role=role_arn)
    )
    assert _code_message(error) == CREATE_REFUSAL, f"expected the IdP-type refusal, got {error}"

    # Effect absent: no access mapping was created for this ExternalId.
    absence_error = _client_error(
        lambda: transfer.describe_access(ServerId=server_id, ExternalId=external_id)
    )
    assert _code_message(absence_error) == DESCRIBE_REFUSAL, (
        f"unexpected {absence_error} probing for the never-created access"
    )

    # A different Role does not change the outcome.
    other_role_arn = _create_transfer_role(ctx)
    error_other_role = _client_error(
        lambda: transfer.create_access(
            ServerId=server_id, ExternalId=external_id, Role=other_role_arn
        )
    )
    assert _code_message(error_other_role) == CREATE_REFUSAL, (
        f"expected the same rejection with a different Role, got {error_other_role}"
    )

    # Neither does a different ExternalId.
    other_external_id = "S-1-5-21-111111111-222222222-333333333-1002"
    error_other_external_id = _client_error(
        lambda: transfer.create_access(
            ServerId=server_id, ExternalId=other_external_id, Role=role_arn
        )
    )
    assert _code_message(error_other_external_id) == CREATE_REFUSAL, (
        f"expected the same rejection with a different ExternalId, got {error_other_external_id}"
    )

    # Retrying the original call is rejected identically.
    error_repeat = _client_error(
        lambda: transfer.create_access(ServerId=server_id, ExternalId=external_id, Role=role_arn)
    )
    assert _code_message(error_repeat) == CREATE_REFUSAL, (
        f"expected the identical rejection on retry, got {error_repeat}"
    )


def _create_transfer_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "transfer.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _create_api_gateway_idp_server(ctx):
    iam = ctx.client("iam")
    apigw = ctx.client("apigateway")
    transfer = ctx.client("transfer")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    api_name = ctx.unique_name("sim2real-transfer-idp-api-")
    api_id = apigw.create_rest_api(
        name=api_name,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="AWS_IAM"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    stage_name = "sim2real"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    url = ctx.rest_api_url(api_id, stage_name)

    invocation_role_name = ctx.unique_name("sim2real-transfer-invoke-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "transfer.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    invocation_role_arn = iam.create_role(
        RoleName=invocation_role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=invocation_role_name))

    policy_name = "invoke-api"
    invoke_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "execute-api:Invoke",
                "Resource": f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=invocation_role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(invoke_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=invocation_role_name, PolicyName=policy_name)
    )

    return transfer.create_server(
        IdentityProviderType="API_GATEWAY",
        IdentityProviderDetails={"Url": url, "InvocationRole": invocation_role_arn},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ServerId"]


def _code_message(error):
    return error.get("Code"), error.get("Message")


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected real AWS to reject this call, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

