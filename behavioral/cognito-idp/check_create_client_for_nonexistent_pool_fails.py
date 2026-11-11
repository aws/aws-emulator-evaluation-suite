"""create-client-for-nonexistent-pool-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-client-for-nonexistent-pool-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: CreateUserPoolClient against an unknown pool MUST fail,
    while the identical call against a real pool succeeds."""
    c = ctx.client("cognito-idp")

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    client_name = ctx.unique_name("sim2real-behav-cip-client-")
    client = c.create_user_pool_client(UserPoolId=pool_id, ClientName=client_name)["UserPoolClient"]
    client_id = client["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    assert client["ClientName"] == client_name, (
        f"positive control: expected client name {client_name!r}, got {client.get('ClientName')!r}"
    )
    described = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert described["ClientId"] == client_id, (
        f"positive control: independent read did not find the created client, got {described.get('ClientId')!r}"
    )

    bogus_id = f"{ctx.region}_" + uuid.uuid4().hex[:9]
    try:
        c.create_user_pool_client(
            UserPoolId=bogus_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-")
        )
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for bogus pool id, got {code}"
    )
    # AWS returns this refusal with an empty message.
    assert message == "", f"expected an empty message for the bogus pool id, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
