"""describe-nonexistent-user-pool-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-user-pool-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: DescribeUserPool for an unknown pool id MUST fail,
    with a positive control proving the same call still works for a real pool —
    otherwise a target that rejects every DescribeUserPool call would score green."""
    c = ctx.client("cognito-idp")

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    # the check deletes the pool itself; cleanup covers an early failure
    ctx.on_cleanup(lambda _id=pool_id: _delete_pool_if_present(c, _id))

    desc = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert desc["Id"] == pool_id, f"positive control failed: expected {pool_id}, got {desc.get('Id')}"
    c.delete_user_pool(UserPoolId=pool_id)

    deleted_code, deleted_message = _describe_error(c, pool_id)
    assert deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {deleted_code}"
    )
    expected_deleted = f"User pool {pool_id} does not exist."
    assert deleted_message == expected_deleted, f"expected message {expected_deleted!r}, got {deleted_message!r}"

    bogus_id = f"{ctx.region}_" + uuid.uuid4().hex[:9]
    bogus_code, bogus_message = _describe_error(c, bogus_id)
    assert bogus_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for bogus pool id, got {bogus_code}"
    )
    expected_bogus = f"User pool {bogus_id} does not exist."
    assert bogus_message == expected_bogus, f"expected message {expected_bogus!r}, got {bogus_message!r}"


def _describe_error(c, pool_id: str) -> tuple[str, str]:
    try:
        result = c.describe_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but DescribeUserPool SUCCEEDED and returned {result!r}")


def _delete_pool_if_present(c, pool_id: str) -> None:
    try:
        c.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
