"""set-identity-pool-roles-rejects-cross-account-role."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-rejects-cross-account-role"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises, and fail if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

def _account_id(ctx) -> str:
    """Caller account id."""
    return ctx.account

def _ghost_role_arn(ctx) -> str:
    """A well-formed same-account role ARN that does not exist."""
    return f"arn:aws:iam::{_account_id(ctx)}:role/sim2real-behav-nonexistent-role-xyz"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles refuses a role ARN of another account with AccessDeniedException
    "Cross-account pass role is not allowed." and leaves the stored Roles unchanged, while a
    same-account ARN is accepted and stored first."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)

    own_role = _ghost_role_arn(ctx)
    # positive control: a same-account role ARN is accepted; a refusal raises here.
    ev.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": own_role})
    baseline = ev.get_identity_pool_roles(IdentityPoolId=pool_id).get("Roles", {})
    assert baseline == {"unauthenticated": own_role}, (
        f"positive control did not persist as configured, got {baseline}"
    )

    foreign_role = "arn:aws:iam::111122223333:role/sim2real-behav-foreign-role"
    code, message = _error(
        lambda: ev.set_identity_pool_roles(
            IdentityPoolId=pool_id, Roles={"unauthenticated": foreign_role}
        )
    )
    assert code == "AccessDeniedException", (
        f"expected cross-account role ARN to be rejected with AccessDeniedException, got {code}"
    )
    assert message == "Cross-account pass role is not allowed.", (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )

    stored = ev.get_identity_pool_roles(IdentityPoolId=pool_id).get("Roles", {})
    assert stored == baseline, (
        f"expected the rejected cross-account call to leave prior Roles untouched, got {stored}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
