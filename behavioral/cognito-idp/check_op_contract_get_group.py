"""op-contract-get-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-group"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGroup returns the group's stored fields; an unknown GroupName 404s."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    group_name = ctx.unique_name("sim2real-behav-group-")
    idp.create_group(GroupName=group_name, UserPoolId=pool_id, Description="fidelity check group", Precedence=5)

    got = idp.get_group(GroupName=group_name, UserPoolId=pool_id)["Group"]
    assert got["GroupName"] == group_name, got
    assert got["Description"] == "fidelity check group", got
    assert got["Precedence"] == 5, got
    assert got["UserPoolId"] == pool_id, got
    assert "CreationDate" in got, got

    err = _client_error(lambda: idp.get_group(GroupName=group_name + "-missing", UserPoolId=pool_id))
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    want = "Group not found."
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
