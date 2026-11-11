"""delete-last-user-pool-client-secret-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-last-user-pool-client-secret-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteUserPoolClientSecret of a client's only secret is refused with
    InvalidParameterException "Cannot delete the only client secret." and keeps it; after a second
    secret is added the same delete succeeds, leaving only the new one."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-client-"), GenerateSecret=True
    )["UserPoolClient"]["ClientId"]

    secrets = idp.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecrets"
    ]
    assert len(secrets) == 1, f"expected exactly 1 secret on a freshly-created client, got {secrets}"
    only_secret_id = secrets[0]["ClientSecretId"]

    code, message = _error(
        lambda: idp.delete_user_pool_client_secret(
            UserPoolId=pool_id, ClientId=client_id, ClientSecretId=only_secret_id
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "Cannot delete the only client secret.", f"unexpected message {message!r}"

    remaining = idp.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecrets"
    ]
    assert len(remaining) == 1 and remaining[0]["ClientSecretId"] == only_secret_id, (
        f"the sole secret must survive a rejected delete attempt, got {remaining}"
    )

    # Restore: rotate in a second secret, then the identical delete call must now succeed.
    new_secret_id = idp.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecretDescriptor"
    ]["ClientSecretId"]
    idp.delete_user_pool_client_secret(
        UserPoolId=pool_id, ClientId=client_id, ClientSecretId=only_secret_id
    )
    after_restore = {
        s["ClientSecretId"]
        for s in idp.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
            "ClientSecrets"
        ]
    }
    assert after_restore == {new_secret_id}, (
        f"expected only the rotated-in secret to remain after the identical delete succeeded, "
        f"got {after_restore}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
