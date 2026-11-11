"""prevent-user-existence-errors-masks-unknown-user."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "prevent-user-existence-errors-masks-unknown-user"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"
USER_AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _client_error(fn) -> ClientError | None:
    """Run fn and return the ClientError it raised, or None if it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """For an unknown user, a LEGACY client's InitiateAuth and ForgotPassword fail with
    UserNotFoundException, while an ENABLED client answers NotAuthorizedException with the same message
    as a wrong password and fabricates CodeDeliveryDetails; a correct login still gets tokens."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    def _make_client(mode: str) -> str:
        cid = c.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
            ExplicitAuthFlows=list(USER_AUTH_FLOWS),
            GenerateSecret=False,
            PreventUserExistenceErrors=mode,
        )["UserPoolClient"]["ClientId"]
        ctx.on_cleanup(
            lambda _p=pool_id, _c=cid: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
        )
        return cid

    masked_client = _make_client("ENABLED")
    legacy_client = _make_client("LEGACY")

    described = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=masked_client)[
        "UserPoolClient"
    ]
    assert described.get("PreventUserExistenceErrors") == "ENABLED", (
        f"DescribeUserPoolClient must round-trip PreventUserExistenceErrors=ENABLED, got "
        f"{described.get('PreventUserExistenceErrors')}"
    )

    known = ctx.unique_name("sim2real-behav-cipuser")
    c.admin_create_user(UserPoolId=pool_id, Username=known, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=known: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=known, Password=PASSWORD, Permanent=True
    )
    ghost = ctx.unique_name("sim2real-behav-cipghost")

    def _auth(client_id: str, username: str, password: str):
        return lambda: c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )

    # --- LEGACY discloses that the user does not exist ---
    legacy_err = _client_error(_auth(legacy_client, ghost, PASSWORD))
    assert legacy_err is not None, "InitiateAuth for a nonexistent user must not succeed"
    legacy_code = legacy_err.response.get("Error", {}).get("Code")
    assert legacy_code == "UserNotFoundException", (
        f"a LEGACY client must disclose UserNotFoundException for an unknown user, got "
        f"{legacy_code}"
    )

    # --- ENABLED masks it, and masks it identically to a wrong password ---
    ghost_err = _client_error(_auth(masked_client, ghost, PASSWORD))
    assert ghost_err is not None, "InitiateAuth for a nonexistent user must not succeed"
    ghost_code = ghost_err.response.get("Error", {}).get("Code")
    assert ghost_code == "NotAuthorizedException", (
        f"an ENABLED client must mask an unknown user as NotAuthorizedException, got "
        f"{ghost_code}"
    )

    wrong_pw_err = _client_error(_auth(masked_client, known, "Wr0ng-Passw0rd!"))
    assert wrong_pw_err is not None, "InitiateAuth with a wrong password must not succeed"
    wrong_pw_code = wrong_pw_err.response.get("Error", {}).get("Code")
    assert wrong_pw_code == "NotAuthorizedException", (
        f"a wrong password must fail with NotAuthorizedException, got {wrong_pw_code}"
    )

    ghost_msg = ghost_err.response.get("Error", {}).get("Message")
    wrong_pw_msg = wrong_pw_err.response.get("Error", {}).get("Message")
    assert ghost_msg == wrong_pw_msg, (
        "with PreventUserExistenceErrors=ENABLED the unknown-user and wrong-password "
        f"responses must be indistinguishable; got {ghost_msg!r} vs {wrong_pw_msg!r}"
    )
    assert ghost not in (ghost_msg or ""), (
        f"the masked error must not echo the probed username; message was {ghost_msg!r}"
    )

    # --- the mask extends to account recovery: no existence disclosure there either ---
    forgot_masked = c.forgot_password(ClientId=masked_client, Username=ghost)
    assert "CodeDeliveryDetails" in forgot_masked, (
        "ForgotPassword on an ENABLED client must return fabricated CodeDeliveryDetails for "
        f"an unknown user rather than an error; got keys {sorted(forgot_masked)}"
    )
    forgot_legacy_err = _client_error(
        lambda: c.forgot_password(ClientId=legacy_client, Username=ghost)
    )
    assert forgot_legacy_err is not None, (
        "ForgotPassword on a LEGACY client must fail for an unknown user"
    )
    forgot_legacy_code = forgot_legacy_err.response.get("Error", {}).get("Code")
    assert forgot_legacy_code == "UserNotFoundException", (
        f"ForgotPassword on a LEGACY client must disclose UserNotFoundException, got "
        f"{forgot_legacy_code}"
    )

    # --- effect absent: masking did not create the probed user ---
    ghost_lookup = _client_error(
        lambda: c.admin_get_user(UserPoolId=pool_id, Username=ghost)
    )
    assert ghost_lookup is not None, f"the probed username {ghost} must not exist in the pool"
    assert ghost_lookup.response.get("Error", {}).get("Code") == "UserNotFoundException", (
        f"AdminGetUser for the probed username must be UserNotFoundException, got "
        f"{ghost_lookup.response.get('Error', {}).get('Code')}"
    )

    # --- control: masking does not break the positive path ---
    result = _auth(masked_client, known, PASSWORD)()["AuthenticationResult"]
    assert result.get("AccessToken"), (
        "a correct credential on the ENABLED client must still issue an AccessToken"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
