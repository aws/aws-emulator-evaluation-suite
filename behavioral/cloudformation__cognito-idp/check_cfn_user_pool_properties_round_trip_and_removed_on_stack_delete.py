"""cfn-user-pool-properties-round-trip-and-removed-on-stack-delete."""
from __future__ import annotations

import json
import ssl
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-user-pool-properties-round-trip-and-removed-on-stack-delete"
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
    """A CFN-deployed AWS::Cognito::UserPool describes with the template's name and password
    policy, every Fn::GetAtt attribute the template outputs matches Cognito's own answer, and
    deleting the stack in-band makes DescribeUserPool raise ResourceNotFoundException."""
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    stack_name = ctx.unique_name("sim2real-behav-cogpoolstack-")
    pool_name = ctx.unique_name("sim2real-behav-cogpool-")
    declared_policy = {
        "MinimumLength": 10,
        "RequireUppercase": True,
        "RequireLowercase": True,
        "RequireNumbers": True,
        "RequireSymbols": False,
    }

    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Pool": {
                    "Type": "AWS::Cognito::UserPool",
                    "Properties": {
                        "UserPoolName": pool_name,
                        "DeletionProtection": "INACTIVE",
                        "Policies": {"PasswordPolicy": declared_policy},
                    },
                },
            },
            "Outputs": {
                "PoolRef": {"Value": {"Ref": "Pool"}},
                "PoolGetAttArn": {"Value": {"Fn::GetAtt": ["Pool", "Arn"]}},
                "PoolGetAttProviderName": {"Value": {"Fn::GetAtt": ["Pool", "ProviderName"]}},
                "PoolGetAttProviderURL": {"Value": {"Fn::GetAtt": ["Pool", "ProviderURL"]}},
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
    getatt_arn = outputs["PoolGetAttArn"]
    getatt_provider_name = outputs["PoolGetAttProviderName"]
    getatt_provider_url = outputs["PoolGetAttProviderURL"]

    pool = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert pool["Id"] == pool_id, f"expected Id {pool_id!r}, got {pool['Id']!r}"
    assert pool["Name"] == pool_name, f"expected Name {pool_name!r}, got {pool['Name']!r}"
    policy = pool["Policies"]["PasswordPolicy"]
    for key, expected in declared_policy.items():
        assert policy[key] == expected, f"policy.{key}: expected {expected!r}, got {policy[key]!r}"
    assert pool["Arn"] == getatt_arn, (
        f"Fn::GetAtt Arn {getatt_arn!r} does not match describe_user_pool's Arn {pool['Arn']!r}"
    )
    assert getatt_provider_url == f"https://{getatt_provider_name}", (
        f"Fn::GetAtt ProviderURL {getatt_provider_url!r} should be https:// plus "
        f"Fn::GetAtt ProviderName {getatt_provider_name!r}"
    )
    issuer = _oidc_issuer(cognito, pool_id, ctx.http_verify)
    assert issuer == getatt_provider_url, (
        f"the pool's own OIDC discovery document names issuer {issuer!r}, which should match "
        f"Fn::GetAtt ProviderURL {getatt_provider_url!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )

    code, message = _error(lambda: cognito.describe_user_pool(UserPoolId=pool_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"User pool {pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _oidc_issuer(client, pool_id: str, verify) -> str:
    """The pool's own OpenID-Connect discovery document issuer, over the client's own endpoint."""
    url = f"{client.meta.endpoint_url.rstrip('/')}/{pool_id}/.well-known/openid-configuration"
    with urllib.request.urlopen(url, timeout=30, context=_ssl_context(verify)) as resp:  # noqa: S310
        return json.loads(resp.read().decode())["issuer"]


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


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
