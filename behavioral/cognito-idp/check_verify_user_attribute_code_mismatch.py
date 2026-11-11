"""verify-user-attribute-code-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-user-attribute-code-mismatch"
GROUP = 'error-semantics'
SERVICES = ['cognito-idp']

PASSWORD = "Str0ngPassw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because a
    target accepting a wrong code must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateUserAttributes on email sends a verification code, and VerifyUserAttribute with a wrong code
    fails with CodeMismatchException and its exact message, leaving email_verified false."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), AutoVerifiedAttributes=["email"], UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword="Temp0rar1Pass!", MessageAction="SUPPRESS", UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}])
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    access_token = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]

    new_email = f"{ctx.unique_name('sim2real-behav-cip-newemail-')}@example.com"
    update = c.update_user_attributes(
        AccessToken=access_token,
        UserAttributes=[{"Name": "email", "Value": new_email}],
    )
    assert update["CodeDeliveryDetailsList"], "expected a verification code delivery"

    code, message = _error(
        lambda: c.verify_user_attribute(AccessToken=access_token, AttributeName="email", Code="000000")
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    expected = "Invalid verification code provided, please try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = c.get_user(AccessToken=access_token)
    verified = next(
        (a["Value"] for a in after["UserAttributes"] if a["Name"] == "email_verified"), None
    )
    assert verified == "false", f"email must remain unverified after a mismatched code, got {verified}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
