"""list-user-pool-client-secrets-order-consistent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-user-pool-client-secrets-order-consistent"
GROUP = "ordering"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After AddUserPoolClientSecret, ListUserPoolClientSecrets consistently includes every active secret."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-secrets-pool"),
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-secrets-client"),
        GenerateSecret=True,
    )["UserPoolClient"]["ClientId"]

    initial = cognito.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)
    initial_ids = {s["ClientSecretId"] for s in initial["ClientSecrets"]}
    assert len(initial_ids) == 1, f"expected exactly 1 initial secret, got {initial_ids!r}"

    added = cognito.add_user_pool_client_secret(UserPoolId=pool_id, ClientId=client_id)
    new_id = added["ClientSecretDescriptor"]["ClientSecretId"]
    assert new_id not in initial_ids, (
        f"AddUserPoolClientSecret returned a ClientSecretId already in the initial set: "
        f"new={new_id!r} initial={initial_ids!r}"
    )

    after = cognito.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)
    after_ids = {s["ClientSecretId"] for s in after["ClientSecrets"]}
    assert after_ids == initial_ids | {new_id}, (
        f"ListUserPoolClientSecrets dropped the newest secret: initial={initial_ids!r} "
        f"new={new_id!r} got={after_ids!r}"
    )
    assert len(after["ClientSecrets"]) == 2, (
        f"expected exactly 2 secret entries (no duplicates) after AddUserPoolClientSecret, "
        f"got {after['ClientSecrets']!r}"
    )

    # Repeated reads return the same, complete set (no pagination drift for this API).
    again = cognito.list_user_pool_client_secrets(UserPoolId=pool_id, ClientId=client_id)
    again_ids = {s["ClientSecretId"] for s in again["ClientSecrets"]}
    assert again_ids == after_ids, "ListUserPoolClientSecrets was inconsistent across calls"
    assert "NextToken" not in again or again["NextToken"] is None, (
        f"unexpected NextToken on an unpaged ListUserPoolClientSecrets response: {again!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
