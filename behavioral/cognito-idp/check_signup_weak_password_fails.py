"""signup-weak-password-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signup-weak-password-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

WEAK_PASSWORD = "abc"
STRONG_PASSWORD = "Str0ng!Passw0rd99"

USER_AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            err.response["Error"].get("Message", ""),
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SignUp with a compliant password succeeds unconfirmed, while a too-short one fails with HTTP 400
    InvalidPasswordException and its exact message, and AdminGetUser for that username fails with
    UserNotFoundException."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(USER_AUTH_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    # Positive control: a policy-compliant password succeeds in this same pool/client,
    # so the weak-password rejection below cannot be a blanket SignUp failure.
    strong_username = ctx.unique_name("sim2real-behav-cipuser-strong")
    signup = c.sign_up(ClientId=client_id, Username=strong_username, Password=STRONG_PASSWORD)
    assert signup["UserConfirmed"] is False, (
        f"expected the compliant SignUp to leave the user unconfirmed, got UserConfirmed={signup['UserConfirmed']}"
    )
    ctx.on_cleanup(lambda _p=pool_id, _u=strong_username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    weak_username = ctx.unique_name("sim2real-behav-cipuser-weak")
    code, status, message = _error(
        lambda: c.sign_up(ClientId=client_id, Username=weak_username, Password=WEAK_PASSWORD)
    )
    assert code == "InvalidPasswordException", (
        f"expected InvalidPasswordException for a weak password, got {code}"
    )
    assert status == 400, f"weak-password SignUp: expected HTTP 400, got {status}"
    expected_message = "Password did not conform with policy: Password not long enough"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Effect absent: an independent read (a different operation than SignUp) proves no
    # user was created for the rejected weak-password attempt.
    not_found_code, not_found_status, not_found_message = _error(
        lambda: c.admin_get_user(UserPoolId=pool_id, Username=weak_username)
    )
    assert not_found_code == "UserNotFoundException", (
        f"expected admin_get_user for the rejected username to fail with "
        f"UserNotFoundException, got {not_found_code}"
    )
    assert not_found_status == 400, f"admin_get_user for the rejected username: expected HTTP 400, got {not_found_status}"
    expected_message = "User does not exist."
    assert not_found_message == expected_message, f"expected the message {expected_message!r}, got {not_found_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
