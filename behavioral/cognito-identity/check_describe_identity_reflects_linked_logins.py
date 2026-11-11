"""describe-identity-reflects-linked-logins."""
from __future__ import annotations

import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "describe-identity-reflects-linked-logins"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After linking a developer identity, DescribeIdentity's Logins reflects it without a sync step."""
    client = ctx.client("cognito-identity")
    dev_provider = f"login.{ctx.unique_name('sim2real')}"
    pool_id = _create_pool(ctx, client, DeveloperProviderName=dev_provider)

    dev_user = f"user-{uuid.uuid4()}"
    identity_id = client.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: dev_user}
    )["IdentityId"]

    described = client.describe_identity(IdentityId=identity_id)
    assert described["Logins"] == [dev_provider], (
        f"expected DescribeIdentity Logins=[{dev_provider}] immediately after linking, "
        f"got {described['Logins']}"
    )


def _create_pool(ctx, client, **extra_fields: Any) -> str:
    params = {
        "IdentityPoolName": ctx.unique_name("sim2real-idp-"),
        "AllowUnauthenticatedIdentities": True,
        "IdentityPoolTags": {"sim2real": CHECK},
    }
    params.update(extra_fields)
    pool_id = client.create_identity_pool(**params)["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
