"""sign-up-preferred-username-alias-rejected-until-account-exists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sign-up-preferred-username-alias-rejected-until-account-exists"
GROUP = "aliases"
SERVICES = ["cognito-idp"]

PASSWORD = "Sim2Real!Passw0rd"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> dict:
    """The ClientError ``fn`` raises as {Code, Message}. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """In a preferred_username alias pool SignUp may not carry preferred_username and creates no
    user; the same user signs up without it, and once confirmed sets it and signs in by the alias.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-alias-"),
        AliasAttributes=["preferred_username"],
        UserPoolTags={"sim2real": GROUP},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id), "ResourceNotFoundException"))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-app-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-cip-user-")
    alias = ctx.unique_name("sim2real-behav-cip-pref-")
    err = _error(lambda: c.sign_up(
        ClientId=client_id, Username=username, Password=PASSWORD,
        UserAttributes=[{"Name": "preferred_username", "Value": alias}],
    ))
    assert (err["Code"], err["Message"]) == (
        "InvalidParameterException",
        "Preferred username cannot be provided for unconfirmed account, "
        "since user pool is configured for preferred username alias.",
    ), f"SignUp carrying preferred_username answered {err!r}"
    gone = _error(lambda: c.admin_get_user(UserPoolId=pool_id, Username=username))
    assert (gone["Code"], gone["Message"]) == ("UserNotFoundException", "User does not exist."), (
        f"the refused SignUp left a user behind: {gone!r}"
    )

    # Positive control: the same SignUp without the alias succeeds.
    out = c.sign_up(ClientId=client_id, Username=username, Password=PASSWORD)
    assert out["UserConfirmed"] is False, f"UserConfirmed was {out['UserConfirmed']!r}"
    c.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    c.admin_update_user_attributes(
        UserPoolId=pool_id, Username=username,
        UserAttributes=[{"Name": "preferred_username", "Value": alias}],
    )

    # The alias now resolves to the user, for an admin read and for sign-in.
    by_alias = c.admin_get_user(UserPoolId=pool_id, Username=alias)
    assert by_alias["Username"] == username, f"alias resolved to {by_alias['Username']!r}"
    attrs = {a["Name"]: a["Value"] for a in by_alias["UserAttributes"]}
    assert attrs.get("preferred_username") == alias, (
        f"preferred_username stored as {attrs.get('preferred_username')!r}"
    )
    auth = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": alias, "PASSWORD": PASSWORD},
    )
    token = auth["AuthenticationResult"]["AccessToken"]
    me = c.get_user(AccessToken=token)
    assert me["Username"] == username, f"signing in by the alias returned user {me['Username']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
