"""list-user-pools-returns-created-pool."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-user-pools-returns-created-pool"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly CreateUserPool'd pool appears in ListUserPools and disappears after delete."""
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-behav-pool-")
    pool = idp.create_user_pool(
        PoolName=name,
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": False,
                "RequireLowercase": False,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]
    pool_id = pool["Id"]
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            idp.delete_user_pool(UserPoolId=pool_id)

    ctx.on_cleanup(_cleanup)

    assert _pool_id_in_list(ctx, pool_id), "newly created pool did not appear in ListUserPools"

    idp.delete_user_pool(UserPoolId=pool_id)
    deleted["done"] = True

    assert not _pool_id_in_list(ctx, pool_id), "pool still appears in ListUserPools after delete"


def _pool_id_in_list(ctx, pool_id: str, max_pages: int = 200) -> bool:
    idp = ctx.client("cognito-idp")
    token = None
    for _ in range(max_pages):
        kwargs = {"MaxResults": 60}
        if token:
            kwargs["NextToken"] = token
        resp = idp.list_user_pools(**kwargs)
        for p in resp.get("UserPools", []):
            if p["Id"] == pool_id:
                return True
        token = resp.get("NextToken")
        if not token:
            return False
    raise AssertionError(f"list_user_pools pagination did not terminate within {max_pages} pages")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
