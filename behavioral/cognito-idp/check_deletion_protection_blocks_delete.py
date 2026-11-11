"""deletion-protection-blocks-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletion-protection-blocks-delete"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: DeleteUserPool MUST fail while deletion protection is ACTIVE,
    and the identical call MUST succeed once protection is turned off."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}, DeletionProtection="ACTIVE")["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: _safe_delete_pool(c, _id))
    assert pool_id.startswith(f"{ctx.region}_"), f"expected pool id prefixed {ctx.region}_, got {pool_id!r}"

    desc = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert desc.get("DeletionProtection") == "ACTIVE", (
        f"expected DeletionProtection ACTIVE, got {desc.get('DeletionProtection')}"
    )
    expected_arn = f"arn:aws:cognito-idp:{ctx.region}:{ctx.account}:userpool/{pool_id}"
    assert desc.get("Arn") == expected_arn, f"expected Arn {expected_arn}, got {desc.get('Arn')!r}"

    code, status, message = _error(lambda: c.delete_user_pool(UserPoolId=pool_id))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException while deletion protection is ACTIVE, got {code}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"protected DeleteUserPool: expected HTTP 4xx, got {status}"
    expected_message = "The user pool cannot be deleted because deletion protection is activated. Deletion protection must be inactivated first."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # The pool must still exist after the rejected delete.
    still = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert still["Id"] == pool_id, "pool disappeared despite the delete being rejected"

    # Restore: turn protection off and demand the identical call now succeeds.
    c.update_user_pool(UserPoolId=pool_id, DeletionProtection="INACTIVE")
    updated = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert updated.get("DeletionProtection") == "INACTIVE", (
        f"expected DeletionProtection INACTIVE after update, got {updated.get('DeletionProtection')}"
    )
    assert pool_id in _list_pool_ids(c), "pool absent from ListUserPools before the delete"

    c.delete_user_pool(UserPoolId=pool_id)

    # Gone beat 1: a read by id is ResourceNotFoundException / 400.
    gone_code, gone_status, gone_message = _error(lambda: c.describe_user_pool(UserPoolId=pool_id))
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {gone_code}"
    )
    assert isinstance(gone_status, int) and 400 <= gone_status < 500, f"DescribeUserPool on the deleted pool: expected HTTP 4xx, got {gone_status}"
    expected_message = f"User pool {pool_id} does not exist."
    assert gone_message == expected_message, f"expected the message {expected_message!r}, got {gone_message!r}"

    # Gone beat 2: the listing no longer contains it.
    assert pool_id not in _list_pool_ids(c), "deleted pool still listed by ListUserPools"

    # Gone beat 3: mutations on the dead pool are refused not-found.
    upd_code, upd_status, message = _error(
        lambda: c.update_user_pool(UserPoolId=pool_id, DeletionProtection="INACTIVE")
    )
    assert upd_code == "ResourceNotFoundException" and isinstance(upd_status, int) and 400 <= upd_status < 500, (
        f"UpdateUserPool on the deleted pool: expected (ResourceNotFoundException, 4xx), got {(upd_code, upd_status)}"
    )
    expected_message = ""
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    cli_code, cli_status, message = _error(
        lambda: c.create_user_pool_client(UserPoolId=pool_id, ClientName="sim2real-behav-dead")
    )
    assert cli_code == "ResourceNotFoundException" and isinstance(cli_status, int) and 400 <= cli_status < 500, (
        f"CreateUserPoolClient on the deleted pool: expected (ResourceNotFoundException, 4xx), got {(cli_code, cli_status)}"
    )
    expected_message = ""
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, HTTP status, message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response["Error"].get("Message"),
        )
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _list_pool_ids(client) -> set[str]:
    """Every user pool id in the account, across all ListUserPools pages."""
    ids: set[str] = set()
    for page in client.get_paginator("list_user_pools").paginate(MaxResults=60):
        ids.update(p["Id"] for p in page["UserPools"])
    return ids


def _safe_delete_pool(client, pool_id: str) -> None:
    """Clear deletion protection, then delete; an already-deleted pool is fine."""
    try:
        client.update_user_pool(UserPoolId=pool_id, DeletionProtection="INACTIVE")
        client.delete_user_pool(UserPoolId=pool_id)
    except client.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
