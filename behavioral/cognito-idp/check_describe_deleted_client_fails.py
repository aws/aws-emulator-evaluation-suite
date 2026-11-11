"""describe-deleted-client-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-deleted-client-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: describing a client after its pool is deleted MUST fail."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    # the check deletes the pool itself; deleting the pool also removes its client
    ctx.on_cleanup(lambda _id=pool_id: _delete_pool_if_present(c, _id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"))["UserPoolClient"]["ClientId"]

    live = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert live["ClientId"] == client_id, (
        f"expected positive control describe_user_pool_client to resolve the live client, got {live.get('ClientId')}"
    )

    c.delete_user_pool(UserPoolId=pool_id)

    try:
        c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for client of deleted pool, got {code}"
    )
    expected_message = f"User pool {pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _delete_pool_if_present(c, pool_id: str) -> None:
    try:
        c.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
