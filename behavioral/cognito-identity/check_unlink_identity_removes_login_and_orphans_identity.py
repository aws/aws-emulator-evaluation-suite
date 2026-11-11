"""unlink-identity-removes-login-and-orphans-identity."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unlink-identity-removes-login-and-orphans-identity"
GROUP = 'identity-flow'
SERVICES = ['cognito-identity']

# An unlinked identity does NOT come back with an empty Logins list: DescribeIdentity and
# ListIdentities both project the single sentinel string "DISABLED" in its place, permanently.
DISABLED = "DISABLED"
ERR_NOT_AUTHORIZED = "NotAuthorizedException"
MSG_LOGINS_DONT_MATCH = (
    "Logins don't match. Please include at least one valid login for this identity or identity pool."
)


def _err(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(
        "the identical UnlinkIdentity succeeded a second time; the first one cannot have removed "
        f"the login from the identity's own record: {result!r}"
    )


def _create_identity_pool(ci, ctx, allow_unauth=True, **kwargs):
    name = ctx.unique_name("sim2real-behav-cip-").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_user_pool(ctx, custom_attributes=()):
    """A real user pool + app client; Cognito rejects fabricated third-party tokens."""
    idp = ctx.client("cognito-idp")
    kwargs = {
        "PoolName": ctx.unique_name("sim2real-behav-up-"),
        "UserPoolTags": {"sim2real": CHECK},
    }
    if custom_attributes:
        kwargs["Schema"] = [{
            "Name": attr,
            "AttributeDataType": "String",
            "Mutable": True,
            "Required": False,
            "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "256"},
        } for attr in custom_attributes]
    pool_id = idp.create_user_pool(**kwargs)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="sim2real-behav-client",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    return idp, pool_id, client_id


def _mint_id_token(idp, ctx, pool_id, client_id, attributes=(), groups=()):
    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=list(attributes),
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True,
    )
    for group in groups:
        idp.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group)
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]


# ===== check =====

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnlinkIdentity keeps the identity but replaces its Logins with the sentinel "DISABLED", a
    repeated unlink is refused as Logins don't match, and the same login then gets a NEW IdentityId.
    """
    ci = ctx.client("cognito-identity")

    idp, user_pool_id, client_id = _create_user_pool(ctx)
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    id_token = _mint_id_token(idp, ctx, user_pool_id, client_id)

    pool_id = _create_identity_pool(
        ci, ctx, allow_unauth=True,
        CognitoIdentityProviders=[{
            "ProviderName": provider,
            "ClientId": client_id,
            "ServerSideTokenCheck": False,
        }],
    )

    linked_id = ci.get_id(IdentityPoolId=pool_id, Logins={provider: id_token})["IdentityId"]
    again = ci.get_id(IdentityPoolId=pool_id, Logins={provider: id_token})["IdentityId"]
    assert again == linked_id, (
        f"the same federated login must resolve to one identity, got {linked_id} then {again}"
    )

    described = ci.describe_identity(IdentityId=linked_id)
    assert described["IdentityId"] == linked_id, (
        f"DescribeIdentity echoed {described['IdentityId']} != {linked_id}"
    )
    assert described.get("Logins") == [provider], (
        f"DescribeIdentity must list the linked provider exactly once, got "
        f"{described.get('Logins')!r}"
    )
    creation_date = described["CreationDate"]
    modified_before = described["LastModifiedDate"]

    ci.unlink_identity(
        IdentityId=linked_id,
        Logins={provider: id_token},
        LoginsToRemove=[provider],
    )

    # No polling: the projection change is synchronous on real Cognito -- DescribeIdentity issued
    # immediately after the 200 already reports the sentinel, and it never becomes an empty list.
    unlinked = ci.describe_identity(IdentityId=linked_id)
    assert unlinked["IdentityId"] == linked_id, (
        f"the identity must survive the unlink, got {unlinked!r}"
    )
    assert unlinked.get("Logins") == [DISABLED], (
        f"an unlinked identity's Logins list must be replaced by the single sentinel "
        f"[{DISABLED!r}] -- not emptied, and not left holding {provider!r} -- got "
        f"{unlinked.get('Logins')!r}"
    )
    assert unlinked["CreationDate"] == creation_date, (
        f"CreationDate must not change on unlink: {creation_date} -> {unlinked['CreationDate']}"
    )
    assert unlinked["LastModifiedDate"] > modified_before, (
        f"the unlink is a mutation of the identity and must advance LastModifiedDate: "
        f"{modified_before} -> {unlinked['LastModifiedDate']}"
    )

    listed = {i["IdentityId"]: i.get("Logins") for i in
              ci.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]}
    assert linked_id in listed, (
        f"the unlinked identity must still be listed in the pool, got {sorted(listed)}"
    )
    assert listed[linked_id] == [DISABLED], (
        f"ListIdentities must project the same sentinel as DescribeIdentity for the unlinked "
        f"identity, got {listed[linked_id]!r}"
    )

    # Effect absent, proven by the operation itself: replaying the byte-identical UnlinkIdentity
    # that just succeeded is now refused, because the identity no longer holds that login. This is
    # the assertion an emulator that merely FILTERS the Logins projection cannot pass.
    replay_code, replay_msg = _err(lambda: ci.unlink_identity(
        IdentityId=linked_id, Logins={provider: id_token}, LoginsToRemove=[provider],
    ))
    assert replay_code == ERR_NOT_AUTHORIZED, (
        f"unlinking a login the identity no longer holds must be {ERR_NOT_AUTHORIZED}, got "
        f"{replay_code!r}"
    )
    assert replay_msg == MSG_LOGINS_DONT_MATCH, (
        f"the refusal must be about the supplied Logins not matching the identity "
        f"({MSG_LOGINS_DONT_MATCH!r}), which is what identifies it as a consequence of the "
        f"unlink rather than a generic authorization failure: {replay_msg!r}"
    )

    # A new id proves the provider->identity linkage was dropped, not just filtered from responses.
    relinked_id = ci.get_id(IdentityPoolId=pool_id, Logins={provider: id_token})["IdentityId"]
    assert relinked_id != linked_id, (
        f"after unlinking, the same login must mint a new identity, but GetId returned the "
        f"original {linked_id}"
    )
    relinked = ci.describe_identity(IdentityId=relinked_id)
    assert relinked.get("Logins") == [provider], (
        f"the new identity must carry the provider link, got {relinked.get('Logins')!r}"
    )

    # Both identities coexist, and the two Logins projections are what tells them apart.
    final = {i["IdentityId"]: i.get("Logins") for i in
             ci.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]}
    assert final.get(linked_id) == [DISABLED] and final.get(relinked_id) == [provider], (
        f"the orphaned identity must remain in the pool alongside the new one, each with its own "
        f"Logins projection, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
