"""op-contract-forgot-password."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-forgot-password"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ForgotPassword returns a masked EMAIL CodeDeliveryDetails for a confirmed user and, under the
    LEGACY existence-error policy, fails with UserNotFoundException and its exact message for an
    unknown username without creating it; once that user is created the same call succeeds."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
        PreventUserExistenceErrors="LEGACY",
    )["UserPoolClient"]["ClientId"]

    def _create_confirmed_user(username: str) -> None:
        idp.admin_create_user(
            UserPoolId=pool_id,
            Username=username,
            UserAttributes=[
                {"Name": "email", "Value": f"{username}@example.com"},
                {"Name": "email_verified", "Value": "true"},
            ],
            MessageAction="SUPPRESS",
            TemporaryPassword="Sim2Real-Temp-1!",
        )
        ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
        # move the user out of FORCE_CHANGE_PASSWORD into CONFIRMED so ForgotPassword applies
        idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password="Sim2Real-Real-1!", Permanent=True)

    username = ctx.unique_name("sim2real-behav-user-")
    _create_confirmed_user(username)

    # success path: a confirmed, known user gets a real code-delivery envelope, masked
    # the same way real Cognito always masks it (independent of the existence-error policy)
    resp = idp.forgot_password(ClientId=client_id, Username=username)
    details = resp["CodeDeliveryDetails"]
    assert details["DeliveryMedium"] == "EMAIL", f"expected EMAIL delivery medium, got {details['DeliveryMedium']!r}"
    assert "*" in details["Destination"], f"expected a masked destination address, got {details['Destination']!r}"
    assert f"{username}@example.com" not in details["Destination"], (
        f"real email address leaked unmasked in Destination {details['Destination']!r}"
    )

    # negative: LEGACY existence-error policy surfaces UserNotFoundException for a
    # username that was never created (no masking). The positive control above proves
    # the pool/client are otherwise healthy, so this can't be "every ForgotPassword fails".
    unknown_username = ctx.unique_name("sim2real-behav-nouser-")
    code = _error(lambda: idp.forgot_password(ClientId=client_id, Username=unknown_username))
    assert code == ("UserNotFoundException", "Username/client id combination not found."), (
        f"expected UserNotFoundException, got {code!r}"
    )

    # effect absent: the refused call did not create a shadow user as a side effect
    lookup_code = _error(lambda: idp.admin_get_user(UserPoolId=pool_id, Username=unknown_username))
    assert lookup_code == ("UserNotFoundException", "User does not exist."), (
        f"unknown_username must still not exist after the refusal, got lookup code {lookup_code!r}"
    )

    # restore: the identical call, on the identical client, now succeeds once the
    # username exists -- proving the refusal was specifically about existence, not
    # some property of the client config or the username's shape
    _create_confirmed_user(unknown_username)
    restored_resp = idp.forgot_password(ClientId=client_id, Username=unknown_username)
    assert "CodeDeliveryDetails" in restored_resp, (
        "identical ForgotPassword call must succeed once the username exists"
    )


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, so an
    emulator accepting a call real AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
