"""describe-client-from-other-pool-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-client-from-other-pool-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: a client id MUST NOT resolve under a different pool."""
    c = ctx.client("cognito-idp")
    pool_a = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_a: c.delete_user_pool(UserPoolId=_id))
    pool_b = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_b: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_a, ClientName=ctx.unique_name("sim2real-behav-cip-client-"))["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_a, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    # positive control: the client genuinely exists and is describable through its real pool.
    described = c.describe_user_pool_client(UserPoolId=pool_a, ClientId=client_id)["UserPoolClient"]
    assert described["ClientId"] == client_id, (
        f"expected the client to be describable through its own pool, got {described}"
    )

    try:
        c.describe_user_pool_client(UserPoolId=pool_b, ClientId=client_id)
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a cross-pool client lookup, got {code}"
    )
    expected_message = f"User pool client {client_id} does not exist in user pool {pool_b}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
