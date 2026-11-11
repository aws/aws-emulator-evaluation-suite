"""get-nonexistent-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-nonexistent-group-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: GetGroup for a group that was never created MUST fail.

    Positive control first: GetGroup for a real group in the same pool MUST succeed.
    Without it, a target that rejects every GetGroup call would pass this check too.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    real_name = ctx.unique_name("sim2real-behav-cip-group-")
    c.create_group(UserPoolId=pool_id, GroupName=real_name)
    got = c.get_group(UserPoolId=pool_id, GroupName=real_name)["Group"]
    assert got["GroupName"] == real_name, (
        f"positive control: expected GetGroup to return {real_name}, got {got}"
    )

    bogus_name = ctx.unique_name("sim2real-behav-cip-nogroup-")

    code, message = _error(lambda: c.get_group(UserPoolId=pool_id, GroupName=bogus_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for unknown group, got {code}"
    )
    expected = "Group not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
