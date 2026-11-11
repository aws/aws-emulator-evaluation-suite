"""resend-confirmation-code-and-code-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resend-confirmation-code-and-code-mismatch"
GROUP = 'error-semantics'
SERVICES = ['cognito-idp']

PASSWORD = "Str0ngPassw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResendConfirmationCode returns EMAIL delivery details for an UNCONFIRMED user; ConfirmSignUp with a
    wrong code fails with CodeMismatchException and its exact message and leaves the user UNCONFIRMED,
    and AdminConfirmSignUp then confirms the user."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), AutoVerifiedAttributes=["email"], UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    username = ctx.unique_name("sim2real-behav-cip-resend-")
    c.sign_up(
        ClientId=client_id,
        Username=username,
        Password=PASSWORD,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    resend = c.resend_confirmation_code(ClientId=client_id, Username=username)
    assert resend["CodeDeliveryDetails"]["DeliveryMedium"] == "EMAIL", resend["CodeDeliveryDetails"]

    code, message = _rejection(
        lambda: c.confirm_sign_up(ClientId=client_id, Username=username, ConfirmationCode="000000")
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    expected_message = "Invalid verification code provided, please try again."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "UNCONFIRMED", f"user should remain UNCONFIRMED, got {status}"

    # Positive control: the rejection above is code-specific, not a blanket
    # "ConfirmSignUp/this pool can never confirm anyone" stub -- a legitimate
    # confirmation path for this same user still succeeds afterward.
    c.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    confirmed_status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert confirmed_status == "CONFIRMED", f"expected CONFIRMED after AdminConfirmSignUp, got {confirmed_status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
