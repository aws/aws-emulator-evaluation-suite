"""delete-user-pool-client-secret-nonexistent-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-user-pool-client-secret-nonexistent-id-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _secret_ids(c, pool_id, client_id):
    return {
        s["ClientSecretId"]
        for s in c.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
            "ClientSecrets"
        ]
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE BOUNDARY: DeleteUserPoolClientSecret with a
    ClientSecretId that was never issued for this client MUST be rejected
    rather than silently succeeding as a no-op."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=True,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    original_id = next(iter(_secret_ids(c, pool_id, client_id)))

    # Positive control: a real, just-created ClientSecretId deletes cleanly, proving the account
    # and this operation are otherwise healthy -- so the coming rejection means "unknown id", not
    # "DeleteUserPoolClientSecret is broken for everything".
    added_id = c.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecretDescriptor"
    ]["ClientSecretId"]
    assert _secret_ids(c, pool_id, client_id) == {original_id, added_id}, (
        f"expected the added secret {added_id!r} visible alongside {original_id!r}"
    )
    c.delete_user_pool_client_secret(
        UserPoolId=pool_id, ClientId=client_id, ClientSecretId=added_id
    )
    after_positive_control = _secret_ids(c, pool_id, client_id)
    assert after_positive_control == {original_id}, (
        f"positive-control delete of a real secret {added_id!r} should leave only "
        f"{original_id!r}, got {after_positive_control!r}"
    )

    # Negative: a ClientSecretId that was never issued for this client must be rejected.
    code, message = _error(
        lambda: c.delete_user_pool_client_secret(
            UserPoolId=pool_id,
            ClientId=client_id,
            ClientSecretId="0123456789abcdef0123456789abcdef",
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent ClientSecretId, got {code}"
    )
    assert message == "Client secret does not exist", f"unexpected message {message!r}"

    # Effect-absent, via an independent read: the rejected call must not have touched the
    # client's one remaining, real secret.
    final_ids = _secret_ids(c, pool_id, client_id)
    assert final_ids == {original_id}, (
        f"the rejected delete must not change the secret set: expected {{{original_id!r}}}, "
        f"got {final_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
