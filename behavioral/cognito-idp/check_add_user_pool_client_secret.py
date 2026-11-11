"""add-user-pool-client-secret."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "add-user-pool-client-secret"
GROUP = 'user-pool-client-lifecycle'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddUserPoolClientSecret adds a second, distinct secret listed by ListUserPoolClientSecrets;
    DeleteUserPoolClientSecret removes it while the client's original secret is unchanged."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c)
    client = _new_client(ctx, c, pool_id, GenerateSecret=True)
    client_id = client["ClientId"]
    original_secret = client["ClientSecret"]
    assert original_secret, "CreateUserPoolClient with GenerateSecret=True returned no ClientSecret"

    added = c.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)[
        "ClientSecretDescriptor"
    ]
    new_secret_id = added["ClientSecretId"]
    new_secret_value = added["ClientSecretValue"]
    assert new_secret_value, "AddUserPoolClientSecret returned no ClientSecretValue"
    assert new_secret_value != original_secret, (
        f"new secret value must differ from the original, both were {new_secret_value!r}"
    )

    secret_ids = [
        s["ClientSecretId"]
        for s in c.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
            "ClientSecrets"
        ]
    ]
    assert new_secret_id in secret_ids, "new secret missing from ListUserPoolClientSecrets"

    c.delete_user_pool_client_secret(
        UserPoolId=pool_id, ClientId=client_id, ClientSecretId=new_secret_id
    )
    secret_ids_after = [
        s["ClientSecretId"]
        for s in c.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)[
            "ClientSecrets"
        ]
    ]
    assert new_secret_id not in secret_ids_after, "secret still listed after delete"

    # The original secret must be untouched by adding/removing the extra one.
    desc = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert desc["ClientSecret"] == original_secret, (
        f"original secret must survive add/delete of an extra one: "
        f"expected {original_secret!r}, got {desc['ClientSecret']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
