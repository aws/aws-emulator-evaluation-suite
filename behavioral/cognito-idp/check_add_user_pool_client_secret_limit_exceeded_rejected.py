"""add-user-pool-client-secret-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "add-user-pool-client-secret-limit-exceeded-rejected"
GROUP = "ordering"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-secretslimit"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddUserPoolClientSecret rejects creating a 3rd secret once the 2-secret cap is reached,
    and the cap is enforced on the CURRENT count, not a lifetime call count: deleting one of the
    2 secrets and adding again succeeds, proving the earlier rejection was a live state check."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-secretslimit-pool"),
        DeletionProtection="INACTIVE",
        UserPoolTags=_TAGS,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-secretslimit-client"),
        GenerateSecret=True,
    )["UserPoolClient"]["ClientId"]

    # Positive control: 1 secret already exists from CreateUserPoolClient; add one more to reach
    # the cap of 2. This proves the account/credentials are healthy for this call before we rely
    # on a rejection meaning something.
    second_secret_id = cognito.add_user_pool_client_secret(
        UserPoolId=pool_id, ClientId=client_id
    )["ClientSecretDescriptor"]["ClientSecretId"]

    code, message = _error(
        lambda: cognito.add_user_pool_client_secret(
            UserPoolId=pool_id, ClientId=client_id
        )
    )
    assert (code, message) == ("LimitExceededException", "Client secrets cannot exceed limit of 2 secrets."), (
        f"expected LimitExceededException when exceeding the 2-secret cap, got {(code, message)!r}"
    )

    # The pre-existing 2 secrets must remain untouched by the rejected attempt.
    secrets = cognito.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)
    assert len(secrets["ClientSecrets"]) == 2, secrets["ClientSecrets"]

    # Restore: the cap forbids a 3rd secret only while 2 are active. Free a slot by deleting the
    # one we added, then prove AddUserPoolClientSecret is not permanently wedged for this client.
    cognito.delete_user_pool_client_secret(
        UserPoolId=pool_id, ClientId=client_id, ClientSecretId=second_secret_id
    )
    freed = cognito.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)
    assert len(freed["ClientSecrets"]) == 1, freed["ClientSecrets"]

    restored_id = cognito.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecretDescriptor"
    ]["ClientSecretId"]
    restored = cognito.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)
    restored_ids = {s["ClientSecretId"] for s in restored["ClientSecrets"]}
    surviving_id = freed["ClientSecrets"][0]["ClientSecretId"]
    assert restored_ids == {surviving_id, restored_id}, (
        f"the identical AddUserPoolClientSecret call did not succeed once back under the cap: "
        f"{restored['ClientSecrets']!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
