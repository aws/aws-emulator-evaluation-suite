"""op-contract-resend-confirmation-code."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-resend-confirmation-code"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResendConfirmationCode re-sends the sign-up code with delivery details; unknown username is rejected."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(
        ctx,
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    client_id = _create_client(ctx, pool_id)

    username = ctx.unique_name("sim2real-user-")
    email = f"{username}@example.com"
    password = _password()
    signup = idp.sign_up(
        ClientId=client_id,
        Username=username,
        Password=password,
        UserAttributes=[{"Name": "email", "Value": email}],
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    assert signup["UserConfirmed"] is False, signup

    before = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before["UserStatus"] == "UNCONFIRMED", before["UserStatus"]

    resp = idp.resend_confirmation_code(ClientId=client_id, Username=username)
    details = resp["CodeDeliveryDetails"]
    assert details["DeliveryMedium"] == "EMAIL", details
    assert details["Destination"], details

    # independent read at the destination: resending a code does not itself
    # confirm the user, so the status must be unchanged from before the resend.
    after = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "UNCONFIRMED", after["UserStatus"]

    err = _client_error(
        lambda: idp.resend_confirmation_code(ClientId=client_id, Username="no-such-user")
    )
    assert err.get("Code") == "UserNotFoundException", f"expected UserNotFoundException, got {err!r}"
    want = "Username/client id combination not found."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _password() -> str:
    return "Sim2Real!23Aa"


def _create_user_pool(ctx, **overrides):
    idp = ctx.client("cognito-idp")
    params = {"PoolName": ctx.unique_name("sim2real-behav-pool-")}
    params.update(overrides)
    resp = idp.create_user_pool(**params)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "UserPoolId": pool_id,
        "ClientName": ctx.unique_name("sim2real-behav-client-"),
        "ExplicitAuthFlows": [
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_SRP_AUTH",
        ],
    }
    params.update(overrides)
    resp = idp.create_user_pool_client(**params)
    return resp["UserPoolClient"]["ClientId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
