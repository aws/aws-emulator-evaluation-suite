"""cfn-user-pool-client-properties-round-trip-and-removed-on-stack-delete."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-user-pool-client-properties-round-trip-and-removed-on-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::Cognito::UserPoolClient describes with the template's name, auth flows
    and generated secret, its Ref and Fn::GetAtt ClientId match Cognito's own answer, and deleting
    the stack in-band makes DescribeUserPoolClient raise ResourceNotFoundException."""
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    stack_name = ctx.unique_name("sim2real-behav-cogclientstack-")
    pool_name = ctx.unique_name("sim2real-behav-cogpool-")
    client_name = ctx.unique_name("sim2real-behav-cogclient-")
    declared_auth_flows = sorted(["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])

    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Pool": {
                    "Type": "AWS::Cognito::UserPool",
                    "Properties": {
                        "UserPoolName": pool_name,
                        "DeletionProtection": "INACTIVE",
                    },
                },
                "PoolClient": {
                    "Type": "AWS::Cognito::UserPoolClient",
                    "Properties": {
                        "ClientName": client_name,
                        "UserPoolId": {"Ref": "Pool"},
                        "GenerateSecret": True,
                        "ExplicitAuthFlows": declared_auth_flows,
                        "RefreshTokenValidity": 45,
                    },
                },
            },
            "Outputs": {
                "PoolRef": {"Value": {"Ref": "Pool"}},
                "ClientRef": {"Value": {"Ref": "PoolClient"}},
                "ClientGetAttClientId": {"Value": {"Fn::GetAtt": ["PoolClient", "ClientId"]}},
            },
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body,
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )
    outputs = _outputs(cfn, stack_name)
    pool_id = outputs["PoolRef"]
    client_ref = outputs["ClientRef"]
    getatt_client_id = outputs["ClientGetAttClientId"]

    assert client_ref == getatt_client_id, (
        f"Ref and Fn::GetAtt ClientId disagree on the same resource: "
        f"{client_ref!r} vs {getatt_client_id!r}"
    )

    client = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_ref)[
        "UserPoolClient"
    ]
    assert client["ClientId"] == getatt_client_id, (
        f"Fn::GetAtt ClientId {getatt_client_id!r} does not match "
        f"describe_user_pool_client's ClientId {client['ClientId']!r}"
    )
    assert client["ClientName"] == client_name, (
        f"expected ClientName {client_name!r}, got {client['ClientName']!r}"
    )
    assert client["UserPoolId"] == pool_id, (
        f"expected UserPoolId {pool_id!r}, got {client['UserPoolId']!r}"
    )
    assert sorted(client["ExplicitAuthFlows"]) == declared_auth_flows, (
        f"expected ExplicitAuthFlows {declared_auth_flows!r}, got {sorted(client['ExplicitAuthFlows'])!r}"
    )
    assert client["RefreshTokenValidity"] == 45, (
        f"expected RefreshTokenValidity 45, got {client['RefreshTokenValidity']!r}"
    )
    assert client.get("ClientSecret"), (
        f"GenerateSecret=True should produce a non-empty ClientSecret, got {client.get('ClientSecret')!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )

    code, message = _error(
        lambda: cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_ref)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"User pool {pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _outputs(cfn, stack_name: str) -> dict:
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
