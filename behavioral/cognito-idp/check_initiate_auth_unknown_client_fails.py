"""initiate-auth-unknown-client-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "initiate-auth-unknown-client-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"

USER_AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """InitiateAuth against an unknown app client fails with ResourceNotFoundException and its exact
    message, while the same call against a real client returns an access token."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(USER_AUTH_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    control = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )
    assert control["AuthenticationResult"].get("AccessToken"), (
        "positive control failed: InitiateAuth against a real client with valid creds "
        "returned no AccessToken, so the account/API path cannot support this check"
    )

    unknown_client_id = uuid.uuid4().hex[:26]
    code, message = _error(
        lambda: c.initiate_auth(
            ClientId=unknown_client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": "nobody", "PASSWORD": PASSWORD},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unknown ClientId, got {code}"
    )
    expected = f"User pool client {unknown_client_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
