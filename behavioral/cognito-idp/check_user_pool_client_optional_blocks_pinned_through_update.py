"""user-pool-client-optional-blocks-pinned-through-update."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "user-pool-client-optional-blocks-pinned-through-update"
GROUP = "user-pool-client-lifecycle"
SERVICES = ["cognito-idp"]


def _assert_exact_optional_blocks(client: dict, *, token_validity_units: dict, where: str) -> None:
    """TokenValidityUnits equals exactly ``token_validity_units``; AnalyticsConfiguration and
    RefreshTokenRotation are absent keys, never present-but-empty."""
    assert client.get("TokenValidityUnits") == token_validity_units, (
        f"{where}: expected TokenValidityUnits {token_validity_units!r}, got "
        f"{client.get('TokenValidityUnits')!r}"
    )
    for block in ("AnalyticsConfiguration", "RefreshTokenRotation"):
        assert block not in client, (
            f"{where}: expected {block} to be ABSENT (key not present), got key present "
            f"with value {client[block]!r}"
        )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolClient and DescribeUserPoolClient return TokenValidityUnits as an empty object and
    omit AnalyticsConfiguration and RefreshTokenRotation as absent keys. UpdateUserPoolClient that sets
    TokenValidityUnits leaves it exactly as sent while the other two blocks stay absent."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-")
    )["UserPoolClient"]
    client_id = client["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    _assert_exact_optional_blocks(client, token_validity_units={}, where="CreateUserPoolClient")
    assert client["AuthSessionValidity"] == 3, (
        f"CreateUserPoolClient: expected AuthSessionValidity 3, got {client['AuthSessionValidity']!r}"
    )
    assert client["RefreshTokenValidity"] == 30, (
        f"CreateUserPoolClient: expected RefreshTokenValidity 30, got "
        f"{client['RefreshTokenValidity']!r}"
    )
    assert client["EnableTokenRevocation"] is True, (
        f"CreateUserPoolClient: expected EnableTokenRevocation True, got "
        f"{client['EnableTokenRevocation']!r}"
    )

    described = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    _assert_exact_optional_blocks(described, token_validity_units={}, where="DescribeUserPoolClient")
    assert described["AuthSessionValidity"] == 3, (
        f"DescribeUserPoolClient: expected AuthSessionValidity 3, got "
        f"{described['AuthSessionValidity']!r}"
    )
    assert described["RefreshTokenValidity"] == 30, (
        f"DescribeUserPoolClient: expected RefreshTokenValidity 30, got "
        f"{described['RefreshTokenValidity']!r}"
    )
    assert described["EnableTokenRevocation"] is True, (
        f"DescribeUserPoolClient: expected EnableTokenRevocation True, got "
        f"{described['EnableTokenRevocation']!r}"
    )

    c.update_user_pool_client(
        UserPoolId=pool_id, ClientId=client_id, TokenValidityUnits={"AccessToken": "hours"}
    )
    after_update = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    _assert_exact_optional_blocks(
        after_update,
        token_validity_units={"AccessToken": "hours"},
        where="DescribeUserPoolClient after UpdateUserPoolClient",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
