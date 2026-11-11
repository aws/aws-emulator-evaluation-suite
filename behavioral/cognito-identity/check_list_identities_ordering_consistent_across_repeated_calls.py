"""list-identities-ordering-consistent-across-repeated-calls."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-identities-ordering-consistent-across-repeated-calls"
GROUP = "ordering"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated ListIdentities calls against a pool with no intervening writes return the same
    identities every time; AWS documents no order, so a varying order is accepted."""
    ci = ctx.client("cognito-identity")

    pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    created_ids = [ci.get_id(IdentityPoolId=pool_id)["IdentityId"] for _ in range(6)]
    assert len(set(created_ids)) == 6, "GetId with no Logins unexpectedly reused an IdentityId"

    order_1 = [i["IdentityId"] for i in ci.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]]
    order_2 = [i["IdentityId"] for i in ci.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]]
    order_3 = [i["IdentityId"] for i in ci.list_identities(IdentityPoolId=pool_id, MaxResults=60)["Identities"]]

    assert set(created_ids) <= set(order_1), "ListIdentities is missing identities created moments earlier"
    assert order_1 == order_2 == order_3 or sorted(order_1) == sorted(order_2) == sorted(order_3), (
        "repeated ListIdentities calls against an unmodified pool returned different identities:\n"
        f"{order_1!r}\nvs\n{order_2!r}\nvs\n{order_3!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
