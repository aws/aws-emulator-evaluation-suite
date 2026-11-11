"""unlink-identity-mismatched-login-entry-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unlink-identity-mismatched-login-entry-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UnlinkIdentity refuses a Logins map with no public-provider credential
    (InvalidParameterException), no-ops on a LoginsToRemove entry that was never linked, and
    removes a linked login; UnlinkDeveloperIdentity detaches the developer login."""
    cip = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")

    dev_provider = ctx.unique_name("sim2real-dev-provider-")
    dev_user = "sim2real-unlink-user"

    up = _create_user_pool_and_id_token(ctx, idp)
    provider_name = up["provider_name"]
    id_token = up["id_token"]
    # A syntactically valid public provider that is never linked to any identity: a second user
    # pool this check owns, so no third-party identity provider is named.
    unlinked_pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-userpool-"))[
        "UserPool"
    ]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=unlinked_pool_id))
    unlinked_provider = f"cognito-idp.{ctx.region}.amazonaws.com/{unlinked_pool_id}"

    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": up["client_id"], "ServerSideTokenCheck": False}
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    # Rejection surface: an identity authenticating with ONLY a developer-provider
    # login (no recognized public provider at all) is refused by UnlinkIdentity, and
    # the refusal leaves its existing login in place.
    identity_id = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )["IdentityId"]
    described_before = cip.describe_identity(IdentityId=identity_id)
    assert dev_provider in described_before["Logins"], (
        f"expected {dev_provider!r} among the identity's logins, got {described_before['Logins']!r}"
    )
    code, message = _error(
        lambda: cip.unlink_identity(
            IdentityId=identity_id,
            Logins={dev_provider: dev_user},
            LoginsToRemove=[unlinked_provider],
        )
    )
    assert code == "InvalidParameterException", f"CODE={code}"
    assert message == "Please provide a valid public provider", f"MESSAGE={message!r}"
    described_after_reject = cip.describe_identity(IdentityId=identity_id)
    assert dev_provider in described_after_reject["Logins"], (
        f"the rejected unlink must not touch the existing login, got {described_after_reject['Logins']!r}"
    )

    # No-op surface, on a SEPARATE identity authenticated with a genuinely-linked
    # public (user-pool) login: LoginsToRemove naming a syntactically valid public
    # provider that was never linked to THIS identity is silently accepted with no
    # error, and leaves the identity's real login untouched.
    control_identity_id = cip.get_id(IdentityPoolId=pool_id, Logins={provider_name: id_token})["IdentityId"]
    control_before = cip.describe_identity(IdentityId=control_identity_id)
    assert control_before.get("Logins") == [provider_name], (
        f"expected the control identity to carry exactly {provider_name!r}, got {control_before.get('Logins')!r}"
    )
    cip.unlink_identity(
        IdentityId=control_identity_id,
        Logins={provider_name: id_token},
        LoginsToRemove=[unlinked_provider],
    )
    described_after_noop = cip.describe_identity(IdentityId=control_identity_id)
    assert described_after_noop.get("Logins") == [provider_name], (
        f"a LoginsToRemove entry that was never linked must be a no-op, but the real login "
        f"changed: {described_after_noop.get('Logins')!r}"
    )

    # Same operation, same identity, now naming the login that IS actually linked:
    # UnlinkIdentity genuinely removes it -- proving the no-op above was about the
    # mismatched entry, not about UnlinkIdentity being unable to remove anything here.
    cip.unlink_identity(
        IdentityId=control_identity_id,
        Logins={provider_name: id_token},
        LoginsToRemove=[provider_name],
    )
    control_relinked_id = cip.get_id(IdentityPoolId=pool_id, Logins={provider_name: id_token})["IdentityId"]
    assert control_relinked_id != control_identity_id, (
        "UnlinkIdentity must actually detach a genuinely-linked login: re-authenticating with "
        f"the same token resolved back to the original identity {control_identity_id}"
    )

    # Removing the developer-provider login through the *correct* API
    # (UnlinkDeveloperIdentity, not UnlinkIdentity) succeeds and actually detaches it.
    cip.unlink_developer_identity(
        IdentityId=identity_id,
        IdentityPoolId=pool_id,
        DeveloperProviderName=dev_provider,
        DeveloperUserIdentifier=dev_user,
    )
    # Per the documented contract, an unlinked developer user "will be considered a
    # new identity next time it is seen" -- so re-authenticating the same developer
    # user identifier now mints a genuinely different identity ID.
    new_identity_id = cip.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )["IdentityId"]
    assert new_identity_id != identity_id, (
        f"expected re-authenticating {dev_user!r} after UnlinkDeveloperIdentity to mint a new "
        f"identity, got the original {identity_id}"
    )


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises. A SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_user_pool_and_id_token(ctx, idp):
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-userpool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Behav-Pw1!"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    return {
        "user_pool_id": pool_id,
        "client_id": client_id,
        "id_token": id_token,
        "provider_name": provider_name,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
