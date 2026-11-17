"""list-user-pool-client-secrets-after-client-delete-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-user-pool-client-secrets-after-client-delete-not-found"
GROUP = "state"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListUserPoolClientSecrets lists the secret issued to a live client, and once
    DeleteUserPoolClient removes the client, the same call 404s with ResourceNotFoundException."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"), UserPoolTags=_POOL_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=True,
    )["UserPoolClient"]["ClientId"]

    before = idp.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)
    assert len(before["ClientSecrets"]) == 1, (
        f"expected exactly 1 secret on a GenerateSecret=True client, got {before['ClientSecrets']!r}"
    )

    idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)

    code, message = _error(
        lambda: idp.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"User pool client {client_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the dead client id is also refused by the mutating sibling, not just the list read
    add_code, add_message = _error(
        lambda: idp.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)
    )
    assert add_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from AddUserPoolClientSecret, got {add_code}"
    )
    assert add_message == expected, f"expected message {expected!r}, got {add_message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target that accepts a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
