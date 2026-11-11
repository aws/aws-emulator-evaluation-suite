"""limit-exceeded-client-secret-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "limit-exceeded-client-secret-delete"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteUserPoolClientSecret on a client's only secret fails with InvalidParameterException and its
    exact message and keeps it; after AddUserPoolClientSecret the old secret deletes, leaving the new one."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=True,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    secrets = c.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecrets"
    ]
    assert len(secrets) == 1, f"expected exactly 1 secret on a freshly-created client: {secrets}"
    first_secret_id = secrets[0]["ClientSecretId"]

    # --- Positive control, before the boundary is ever hit: with two secrets present,
    #     deleting one of them is an ordinary, unrestricted call and must succeed.
    c.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)
    c.delete_user_pool_client_secret(
        UserPoolId=pool_id, ClientId=client_id, ClientSecretId=first_secret_id
    )
    after_control = c.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecrets"
    ]
    assert len(after_control) == 1 and after_control[0]["ClientSecretId"] != first_secret_id, (
        f"positive control failed: deleting a non-last secret must succeed and leave exactly "
        f"the other one behind, got {after_control}"
    )
    sole_secret_id = after_control[0]["ClientSecretId"]

    # --- Break exactly one thing: the client is back down to its last remaining secret.
    code, message = _error(
        lambda: c.delete_user_pool_client_secret(
            UserPoolId=pool_id, ClientId=client_id, ClientSecretId=sole_secret_id
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException deleting a client's last remaining secret, got {code}"
    )
    expected = "Cannot delete the only client secret."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_there = c.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecrets"
    ]
    assert len(still_there) == 1 and still_there[0]["ClientSecretId"] == sole_secret_id, (
        f"the sole secret must survive a rejected delete attempt: expected only {sole_secret_id!r}, "
        f"got {still_there}"
    )

    # --- Restore, then the identical call now succeeds: add a second secret back and delete
    #     the original one again -- the same call that was just rejected.
    c.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)
    c.delete_user_pool_client_secret(
        UserPoolId=pool_id, ClientId=client_id, ClientSecretId=sole_secret_id
    )
    remaining = c.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecrets"
    ]
    assert len(remaining) == 1 and remaining[0]["ClientSecretId"] != sole_secret_id, (
        f"expected exactly 1 secret, not {sole_secret_id!r}, after restoring a second secret and "
        f"re-deleting the original one, got {remaining}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
