"""describe-identity-pool-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-identity-pool-nonexistent-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeIdentityPool and ListIdentities on a well-formed but nonexistent pool id answer
    ResourceNotFoundException "IdentityPool '<id>' not found.", while both succeed on a just-created
    pool."""
    ev = ctx.client("cognito-identity")

    pool_id = ev.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ev.delete_identity_pool(IdentityPoolId=pool_id))

    described = ev.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolId"] == pool_id, (
        f"positive control: expected describe to echo {pool_id}, got {described.get('IdentityPoolId')}"
    )
    listed = ev.list_identities(IdentityPoolId=pool_id, MaxResults=10)
    assert listed["IdentityPoolId"] == pool_id, (
        f"positive control: expected list to echo {pool_id}, got {listed.get('IdentityPoolId')}"
    )

    ghost_pool = f"{ctx.region}:00000000-0000-0000-0000-000000000000"
    not_found = ("ResourceNotFoundException", f"IdentityPool '{ghost_pool}' not found.")
    err = _error(lambda: ev.describe_identity_pool(IdentityPoolId=ghost_pool))
    assert err == not_found, (
        f"expected {not_found} describing a nonexistent identity pool, got {err}"
    )
    err_list = _error(lambda: ev.list_identities(IdentityPoolId=ghost_pool, MaxResults=10))
    assert err_list == not_found, (
        f"expected {not_found} listing identities of a nonexistent pool, got {err_list}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
