"""user-pool-client-secret-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-pool-client-secret-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddUserPoolClientSecret returns a new secret value once and lists it beside the original, which
    DescribeUserPoolClient still reports; deleting it again fails with ResourceNotFoundException, and
    deleting the last secret fails with InvalidParameterException, each with its exact message."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    # Real AWS rejects AddUserPoolClientSecret with "client secret not enabled" unless the client
    # was created with GenerateSecret=True; a confidential client already has one secret from
    # creation, so track that initial secret to distinguish it from the one we add ourselves.
    created_client = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-"), GenerateSecret=True
    )["UserPoolClient"]
    client_id = created_client["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    original_secret = created_client.get("ClientSecret")
    assert original_secret

    before = cognito.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)["ClientSecrets"]
    initial_ids = {s["ClientSecretId"] for s in before}
    assert initial_ids, before

    added = cognito.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)["ClientSecretDescriptor"]
    secret_id = added["ClientSecretId"]
    assert secret_id not in initial_ids

    # AddUserPoolClientSecret echoes the raw secret material exactly once, in this response
    # (ListUserPoolClientSecrets never reveals it again).
    assert added.get("ClientSecretValue") and added["ClientSecretValue"] != original_secret, added

    # A client supports up to two simultaneously-active secrets for zero-downtime rotation, so
    # DescribeUserPoolClient keeps reporting the original secret while the new one is also live.
    active_secret = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"][
        "ClientSecret"
    ]
    assert active_secret == original_secret, (active_secret, original_secret)

    listed = cognito.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)["ClientSecrets"]
    ids = {s["ClientSecretId"] for s in listed}
    assert secret_id in ids, listed
    assert initial_ids <= ids, listed

    cognito.delete_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id, ClientSecretId=secret_id)

    listed_after = cognito.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)["ClientSecrets"]
    ids_after = {s["ClientSecretId"] for s in listed_after}
    assert secret_id not in ids_after
    assert initial_ids <= ids_after, listed_after

    code, message = _error(
        lambda: cognito.delete_user_pool_client_secret(
            UserPoolId=pool_id, ClientId=client_id, ClientSecretId=secret_id
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Client secret does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control for the next negative: the delete above genuinely removes a secret when
    # more than one remains. Now only the original is left; AWS refuses to take a client below one
    # secret, so the identical operation on the last remaining id must be rejected, and that
    # secret must still be listed afterward.
    last_id = next(iter(initial_ids))
    code, message = _error(
        lambda: cognito.delete_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id, ClientSecretId=last_id)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = "Cannot delete the only client secret."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    listed_final = cognito.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)["ClientSecrets"]
    assert last_id in {s["ClientSecretId"] for s in listed_final}, listed_final


def _error(fn):
    """Run fn; return the ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
