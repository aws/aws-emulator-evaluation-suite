"""developer-user-unknown-explicit-identity-rejected."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "developer-user-unknown-explicit-identity-rejected"
GROUP = "developer-identity"
SERVICES = ["cognito-identity"]


def _refusal(fn):
    """Call fn(); return the refusal's (Code, Message). An unexpected success raises, so an
    over-permissive target never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be refused, but it SUCCEEDED and returned {result!r}"
    )


def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK},
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Supplying an explicit IdentityId that was never issued in the pool must be rejected, not auto-created."""
    ev = ctx.client("cognito-identity")
    dev_provider = "login.myapp"
    pool_id = _create_pool(ev, ctx, allow_unauth=True, DeveloperProviderName=dev_provider)

    # Positive control: the pool and developer provider are otherwise healthy, so a rejection
    # below is attributable to the fabricated IdentityId and not to a pool that rejects everything.
    control = ev.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: ctx.unique_name("sim2real-behav-devuser-ok-")}
    )
    assert control["IdentityId"], "positive control: expected a real identity id"

    fabricated_identity_id = f"{ctx.region}:00000000-0000-0000-0000-000000000000"
    code, message = _refusal(
        lambda: ev.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id,
            IdentityId=fabricated_identity_id,
            Logins={dev_provider: ctx.unique_name("sim2real-behav-devuser-")},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an IdentityId that does not exist in the pool, "
        f"got {code!r}: {message!r}"
    )
    assert message == f"Identity '{fabricated_identity_id}' not found.", message

    # Effect absent, via an independent read at a different operation: the rejected call did not
    # silently create or link the fabricated identity id as a side effect.
    describe_code, describe_message = _refusal(
        lambda: ev.describe_identity(IdentityId=fabricated_identity_id)
    )
    assert describe_code == "ResourceNotFoundException", (
        f"the rejected call nonetheless left the fabricated identity id describable, "
        f"got {describe_code!r}: {describe_message!r}"
    )
    assert describe_message == f"Identity '{fabricated_identity_id}' not found.", describe_message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
