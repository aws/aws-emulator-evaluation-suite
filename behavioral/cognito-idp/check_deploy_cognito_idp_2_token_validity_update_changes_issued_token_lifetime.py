"""deploy-cognito-idp-2-token-validity-update-changes-issued-token-lifetime."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cognito-idp-2-token-validity-update-changes-issued-token-lifetime"
GROUP = "deploy-update"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!TtlPass9"
_BEFORE_MIN = 60
_AFTER_MIN = 7
_STACK_TIMEOUT_S = 600
# AWS mints exp - iat one second short of the configured validity (3599 for 60 min);
# a 2 s tolerance absorbs that rounding. The 60 -> 7 minute change it
# grades is 3180 s, so the tolerance cannot mask a validity update that did not take effect.
_ROUNDING_S = 2


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An update_stack that changes a deployed app client's AccessTokenValidity takes effect in
    place: the access token minted before the update spans 60 minutes (exp - iat) and the one
    minted afterwards by the same client id spans 7."""
    cfn = ctx.client("cloudformation")
    cognito = ctx.client("cognito-idp")
    stack_name = ctx.unique_name("sim2real-cog-ttl-")

    created = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(stack_name, _BEFORE_MIN),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_stack(cfn, created["StackId"]))
    stack_id = created["StackId"]

    outputs = _wait_stack(cfn, stack_id, "CREATE_COMPLETE")
    pool_id = outputs["UserPoolId"]
    client_id = outputs["UserPoolClientId"]

    user = ctx.unique_name("sim2real-cog-ttluser-")
    cognito.admin_create_user(UserPoolId=pool_id, Username=user, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: _delete_user(cognito, pool_id, user))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=user, Password=_PASSWORD, Permanent=True)

    first = _access_claims(cognito, client_id, user)
    span = first["exp"] - first["iat"]
    assert abs(span - _BEFORE_MIN * 60) <= _ROUNDING_S, (
        f"pre-update access token spans {span!r}s, expected {_BEFORE_MIN * 60} (+/-{_ROUNDING_S})"
    )
    assert first["client_id"] == client_id, f"pre-update token client_id is {first['client_id']!r}"

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack_name, _AFTER_MIN))
    outputs = _wait_stack(cfn, stack_id, "UPDATE_COMPLETE")
    assert outputs["UserPoolClientId"] == client_id, (
        f"changing AccessTokenValidity replaced the client {client_id!r} -> {outputs['UserPoolClientId']!r}"
    )
    validity = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"][
        "AccessTokenValidity"]
    assert validity == _AFTER_MIN, f"client AccessTokenValidity reads {validity!r}, expected {_AFTER_MIN!r}"

    second = _access_claims(cognito, client_id, user)
    span = second["exp"] - second["iat"]
    assert abs(span - _AFTER_MIN * 60) <= _ROUNDING_S, (
        f"post-update access token spans {span!r}s, expected {_AFTER_MIN * 60} (+/-{_ROUNDING_S})"
    )
    assert second["client_id"] == client_id, f"post-update token client_id is {second['client_id']!r}"
    assert second["jti"] != first["jti"], "post-update token reused the pre-update token's jti"




def _access_claims(cognito, client_id: str, user: str) -> dict:
    resp = cognito.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": user, "PASSWORD": _PASSWORD},
    )
    token = resp.get("AuthenticationResult", {}).get("AccessToken")
    assert token, f"InitiateAuth issued no AccessToken: {sorted(resp)!r}"
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _template(stack_name: str, access_minutes: int) -> str:
    return json.dumps({
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "UserPoolName": stack_name + "-pool",
                    "DeletionProtection": "INACTIVE",
                    "UserPoolTags": {"sim2real": CHECK},
                },
            },
            "Client": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": stack_name + "-client",
                    "UserPoolId": {"Ref": "Pool"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                    "AccessTokenValidity": access_minutes,
                    "IdTokenValidity": 60,
                    "RefreshTokenValidity": 1,
                    "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"},
                },
            },
        },
        "Outputs": {
            "UserPoolId": {"Value": {"Ref": "Pool"}},
            "UserPoolClientId": {"Value": {"Ref": "Client"}},
        },
    })


def _wait_stack(cfn, stack_id: str, want: str) -> dict:
    """Poll until the stack leaves *_IN_PROGRESS; a timeout or any other terminal state FAILs."""
    deadline = time.monotonic() + _STACK_TIMEOUT_S
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = desc["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            assert status == want, f"stack reached {status!r}, expected {want!r}"
            return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
        time.sleep(5)
    raise AssertionError(f"stack did not reach {want!r} within {_STACK_TIMEOUT_S}s (last status={status!r})")


def _delete_user(cognito, pool_id: str, username: str) -> None:
    try:
        cognito.admin_delete_user(UserPoolId=pool_id, Username=username)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("UserNotFoundException", "ResourceNotFoundException"):
            raise


def _cleanup_stack(cfn, stack_id: str) -> None:
    status = None
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + _STACK_TIMEOUT_S
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        time.sleep(2)
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} teardown ended in {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
