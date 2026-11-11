"""deploy-cognito-idp-2-password-policy-schema-update-and-client-replacement."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cognito-idp-2-password-policy-schema-update-and-client-replacement"
GROUP = "deploy-update"
SERVICES = ["cognito-idp"]

_OLD_MIN_LENGTH = 8
_NEW_MIN_LENGTH = 14
# 10 characters: satisfies the original MinimumLength=8, violates the tightened 14.
_LOOSE_PASSWORD = "sim2realpw"
# 18 characters: satisfies both policies (no character-class requirements are set).
_STRONG_PASSWORD = "sim2realstrongpass"
_CUSTOM_ATTR = "tier"
_STACK_TIMEOUT_S = 600


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Updating a stack's PasswordPolicy changes what SignUp enforces in place; adding a Schema
    attribute keeps the pool, while flipping create-only GenerateSecret replaces the client, so
    the old client id stops working and the new one requires SECRET_HASH. Users survive both.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cognito-userpoolclient.html
    """
    cfn = ctx.client("cloudformation")
    cognito = ctx.client("cognito-idp")
    stack_name = ctx.unique_name("sim2real-cog-upd-")
    pool_ids: list[str] = []

    created = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(stack_name, _OLD_MIN_LENGTH, with_schema=False, client_secret=False),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_stack(cfn, cognito, created["StackId"], pool_ids))
    stack_id = created["StackId"]

    status, outputs = _wait_stack(cfn, stack_id, "CREATE_COMPLETE")
    assert status == "CREATE_COMPLETE", f"stack create ended in {status!r}, expected 'CREATE_COMPLETE'"
    pool_id = outputs["UserPoolId"]
    client_id = outputs["UserPoolClientId"]
    pool_ids.append(pool_id)
    assert _physical_id(cfn, stack_id, "Pool") == pool_id, "stack resource Pool does not match the UserPoolId output"

    pool = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    got_min = pool["Policies"]["PasswordPolicy"]["MinimumLength"]
    assert got_min == _OLD_MIN_LENGTH, f"deployed MinimumLength is {got_min!r}, expected {_OLD_MIN_LENGTH!r}"
    assert not _has_custom_attr(pool), (
        f"fresh pool already carries custom:{_CUSTOM_ATTR}: {_custom_attr_names(pool)!r}"
    )

    # --- baseline: the loose password is acceptable under the original policy -------------
    early_user = ctx.unique_name("sim2real-cog-early-")
    signed = cognito.sign_up(ClientId=client_id, Username=early_user, Password=_LOOSE_PASSWORD)
    ctx.on_cleanup(lambda: _delete_user(cognito, pool_id, early_user))
    assert signed["UserSub"], f"SignUp under MinimumLength={_OLD_MIN_LENGTH} returned no UserSub: {signed!r}"
    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=early_user)
    early_sub = cognito.admin_get_user(UserPoolId=pool_id, Username=early_user)["Username"]
    assert early_sub == early_user, f"AdminGetUser returned {early_sub!r}, expected {early_user!r}"

    code, message = _error(lambda: cognito.admin_update_user_attributes(
        UserPoolId=pool_id, Username=early_user,
        UserAttributes=[{"Name": f"custom:{_CUSTOM_ATTR}", "Value": "gold"}],
    ))
    assert code == "InvalidParameterException", (
        f"setting custom:{_CUSTOM_ATTR} before the schema declares it returned {code!r}, "
        "expected 'InvalidParameterException'"
    )
    expected_message = f"user.custom:{_CUSTOM_ATTR}: Attribute does not exist in the schema.\n"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    auth = cognito.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": early_user, "PASSWORD": _LOOSE_PASSWORD},
    )
    assert auth.get("AuthenticationResult", {}).get("AccessToken"), (
        f"baseline InitiateAuth on the original client issued no AccessToken: {sorted(auth)!r}"
    )

    # --- update 1: tighten MinimumLength in place -----------------------------------------
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(stack_name, _NEW_MIN_LENGTH, with_schema=False, client_secret=False),
    )
    status, outputs = _wait_stack(cfn, stack_id, "UPDATE_COMPLETE")
    assert status == "UPDATE_COMPLETE", f"update 1 ended in {status!r}, expected 'UPDATE_COMPLETE'"
    assert outputs["UserPoolId"] == pool_id, (
        f"PasswordPolicy update changed UserPoolId {pool_id!r} -> {outputs['UserPoolId']!r}; "
        "it must be an in-place update"
    )
    assert _physical_id(cfn, stack_id, "Pool") == pool_id, "stack resource Pool moved after update 1"
    assert outputs["UserPoolClientId"] == client_id, (
        f"update 1 changed the client id {client_id!r} -> {outputs['UserPoolClientId']!r}"
    )
    got_min = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]["Policies"]["PasswordPolicy"]["MinimumLength"]
    assert got_min == _NEW_MIN_LENGTH, f"after update 1 MinimumLength is {got_min!r}, expected {_NEW_MIN_LENGTH!r}"

    rejected_user = ctx.unique_name("sim2real-cog-loose-")
    ctx.on_cleanup(lambda: _delete_user(cognito, pool_id, rejected_user))
    code, message = _error(lambda: cognito.sign_up(
        ClientId=client_id, Username=rejected_user, Password=_LOOSE_PASSWORD,
    ))
    assert code == "InvalidPasswordException", (
        f"SignUp with a {len(_LOOSE_PASSWORD)}-char password after tightening to "
        f"{_NEW_MIN_LENGTH} returned {code!r}, expected 'InvalidPasswordException'"
    )
    expected_message = "Password did not conform with policy: Password not long enough"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    code, message = _error(lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=rejected_user))
    assert code == "UserNotFoundException", (
        f"the rejected SignUp left a user behind: AdminGetUser returned {code!r}, expected 'UserNotFoundException'"
    )
    assert message == "User does not exist.", f"expected message 'User does not exist.', got {message!r}"

    strong_user = ctx.unique_name("sim2real-cog-strong-")
    signed = cognito.sign_up(ClientId=client_id, Username=strong_user, Password=_STRONG_PASSWORD)
    ctx.on_cleanup(lambda: _delete_user(cognito, pool_id, strong_user))
    assert signed["UserSub"], f"SignUp with a compliant password returned no UserSub: {signed!r}"
    got = cognito.admin_get_user(UserPoolId=pool_id, Username=strong_user)["Username"]
    assert got == strong_user, f"AdminGetUser for the compliant signup returned {got!r}"

    survivor = cognito.admin_get_user(UserPoolId=pool_id, Username=early_user)
    assert survivor["Username"] == early_user, f"pre-update user lookup returned {survivor['Username']!r}"
    assert survivor["UserStatus"] == "CONFIRMED", (
        f"pre-update user status after update 1 is {survivor['UserStatus']!r}, expected 'CONFIRMED'"
    )

    # --- update 2: add a Schema attribute (pool, in place) + flip GenerateSecret (client, replaced)
    # AWS::Cognito::UserPool declares no createOnlyProperties, so a Schema addition keeps the
    # UserPoolId; GenerateSecret on the client is create-only and forces replacement.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(stack_name, _NEW_MIN_LENGTH, with_schema=True, client_secret=True),
    )
    status, outputs = _wait_stack(cfn, stack_id, "UPDATE_COMPLETE")
    assert status == "UPDATE_COMPLETE", f"update 2 ended in {status!r}, expected 'UPDATE_COMPLETE'"
    new_pool_id = outputs["UserPoolId"]
    if new_pool_id not in pool_ids:
        pool_ids.append(new_pool_id)
    new_client_id = outputs["UserPoolClientId"]
    assert new_pool_id == pool_id, (
        f"adding a Schema attribute changed UserPoolId {pool_id!r} -> {new_pool_id!r}; real AWS "
        "updates AWS::Cognito::UserPool Schema in place"
    )
    assert new_client_id != client_id, (
        f"flipping create-only GenerateSecret kept client id {client_id!r}; it must be replaced"
    )
    assert _physical_id(cfn, stack_id, "Client") == new_client_id, "stack resource Client does not match the new output"

    pool = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert _has_custom_attr(pool), (
        f"after update 2 the pool's custom attributes are {_custom_attr_names(pool)!r}, "
        f"expected custom:{_CUSTOM_ATTR}"
    )
    got_min = pool["Policies"]["PasswordPolicy"]["MinimumLength"]
    assert got_min == _NEW_MIN_LENGTH, f"update 2 reset MinimumLength to {got_min!r}"

    survivor = cognito.admin_get_user(UserPoolId=pool_id, Username=early_user)
    assert survivor["Username"] == early_user, f"pre-update user lookup after update 2 returned {survivor['Username']!r}"
    cognito.admin_update_user_attributes(
        UserPoolId=pool_id, Username=early_user,
        UserAttributes=[{"Name": f"custom:{_CUSTOM_ATTR}", "Value": "gold"}],
    )
    attrs = {a["Name"]: a["Value"] for a in
             cognito.admin_get_user(UserPoolId=pool_id, Username=early_user)["UserAttributes"]}
    assert attrs.get(f"custom:{_CUSTOM_ATTR}") == "gold", (
        f"custom:{_CUSTOM_ATTR} on the pre-update user reads {attrs.get(f'custom:{_CUSTOM_ATTR}')!r}, expected 'gold'"
    )

    old_client_desc, message = _error(lambda: cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    assert old_client_desc == "ResourceNotFoundException", (
        f"DescribeUserPoolClient on the replaced client returned {old_client_desc!r}, expected 'ResourceNotFoundException'"
    )
    expected_message = "User pool client does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    code, message = _error(lambda: cognito.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": early_user, "PASSWORD": _LOOSE_PASSWORD},
    ))
    assert code == "ResourceNotFoundException", (
        f"InitiateAuth via the replaced client id returned {code!r}, expected 'ResourceNotFoundException'"
    )
    expected_message = f"User pool client {client_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    code, message = _error(lambda: cognito.initiate_auth(
        ClientId=new_client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": early_user, "PASSWORD": _LOOSE_PASSWORD},
    ))
    assert code == "NotAuthorizedException", (
        f"InitiateAuth on the secret-bearing replacement client without SECRET_HASH returned {code!r}, "
        "expected 'NotAuthorizedException'"
    )
    expected_message = f"Client {new_client_id} is configured with secret but SECRET_HASH was not received"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    secret = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=new_client_id)["UserPoolClient"].get("ClientSecret")
    assert secret, "the replacement client was deployed with GenerateSecret=true but has no ClientSecret"
    auth = cognito.initiate_auth(
        ClientId=new_client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={
            "USERNAME": early_user,
            "PASSWORD": _LOOSE_PASSWORD,
            "SECRET_HASH": _secret_hash(early_user, new_client_id, secret),
        },
    )
    access = auth.get("AuthenticationResult", {}).get("AccessToken")
    assert access, f"InitiateAuth with SECRET_HASH on the replacement client issued no AccessToken: {sorted(auth)!r}"
    claims = _jwt_claims(access)
    assert claims.get("client_id") == new_client_id, (
        f"access token client_id claim is {claims.get('client_id')!r}, expected the replacement {new_client_id!r}"
    )

    # --- delete the stack and grade the teardown ------------------------------------------
    final = _delete_stack_and_wait(cfn, stack_id)
    assert final == "DELETE_COMPLETE", f"delete_stack ended in {final!r}, expected 'DELETE_COMPLETE'"
    code, message = _error(lambda: cognito.describe_user_pool(UserPoolId=pool_id))
    assert code == "ResourceNotFoundException", (
        f"DescribeUserPool after DELETE_COMPLETE returned {code!r}, expected 'ResourceNotFoundException'"
    )
    expected_message = f"User pool {pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _template(stack_name: str, min_length: int, *, with_schema: bool, client_secret: bool) -> str:
    pool_props = {
        "UserPoolName": stack_name + "-pool",
        "DeletionProtection": "INACTIVE",
        "UserPoolTags": {"sim2real": CHECK},
        "Policies": {
            "PasswordPolicy": {
                "MinimumLength": min_length,
                "RequireUppercase": False,
                "RequireLowercase": False,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }
        },
    }
    if with_schema:
        pool_props["Schema"] = [{
            "Name": _CUSTOM_ATTR,
            "AttributeDataType": "String",
            "Mutable": True,
            "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "32"},
        }]
    return json.dumps({
        "Resources": {
            "Pool": {"Type": "AWS::Cognito::UserPool", "Properties": pool_props},
            "Client": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": stack_name + "-client",
                    "UserPoolId": {"Ref": "Pool"},
                    "GenerateSecret": client_secret,
                    "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                },
            },
        },
        "Outputs": {
            "UserPoolId": {"Value": {"Ref": "Pool"}},
            "UserPoolClientId": {"Value": {"Ref": "Client"}},
        },
    })


def _wait_stack(cfn, stack_id: str, want: str) -> tuple[str, dict]:
    """Poll until the stack leaves *_IN_PROGRESS; a timeout is a FAIL naming the last status."""
    deadline = time.monotonic() + _STACK_TIMEOUT_S
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = desc["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            if status != want:
                reasons = [
                    f"{e['LogicalResourceId']}:{e['ResourceStatus']}:{e.get('ResourceStatusReason', '')}"
                    for e in cfn.describe_stack_events(StackName=stack_id)["StackEvents"][:10]
                    if e["ResourceStatus"].endswith("FAILED")
                ]
                raise AssertionError(f"stack reached {status!r}, expected {want!r}; failures: {reasons!r}")
            return status, {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
        time.sleep(5)
    raise AssertionError(f"stack did not reach {want!r} within {_STACK_TIMEOUT_S}s (last status={status!r})")


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"]["PhysicalResourceId"]


def _custom_attr_names(pool: dict) -> list:
    return sorted(a["Name"] for a in pool.get("SchemaAttributes", []) if a["Name"].startswith("custom:"))


def _has_custom_attr(pool: dict) -> bool:
    return f"custom:{_CUSTOM_ATTR}" in _custom_attr_names(pool)


def _secret_hash(username: str, client_id: str, secret: str) -> str:
    digest = hmac.new(secret.encode(), (username + client_id).encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def _jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _delete_user(cognito, pool_id: str, username: str) -> None:
    try:
        cognito.admin_delete_user(UserPoolId=pool_id, Username=username)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("UserNotFoundException", "ResourceNotFoundException"):
            raise


def _delete_stack_and_wait(cfn, stack_id: str) -> str:
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + _STACK_TIMEOUT_S
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            return status
        time.sleep(5)
    return f"TIMEOUT(last={status})"


def _cleanup_stack(cfn, cognito, stack_id: str, pool_ids: list) -> None:
    """Delete the stack, then delete any pool it was tracking that survived it."""
    try:
        status = _delete_stack_and_wait(cfn, stack_id)
    finally:
        for pid in pool_ids:
            try:
                cognito.delete_user_pool(UserPoolId=pid)
            except ClientError as err:
                if err.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} teardown ended in {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
