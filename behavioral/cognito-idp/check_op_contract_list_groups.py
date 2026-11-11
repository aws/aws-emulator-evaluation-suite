"""op-contract-list-groups."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-list-groups"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGroups enumerates all groups created in the pool; a bogus pool id 404s."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    names = {ctx.unique_name(f"sim2real-behav-group-{i}-") for i in range(2)}
    for n in names:
        idp.create_group(GroupName=n, UserPoolId=pool_id)

    listed = {g["GroupName"] for g in idp.list_groups(UserPoolId=pool_id)["Groups"]}
    assert names == listed, f"expected exactly {names}, got {listed}"

    bogus_id = pool_id[:-4] + "zzzz"
    err = _client_error(lambda: idp.list_groups(UserPoolId=bogus_id))
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    want = f"User pool {bogus_id} does not exist."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
