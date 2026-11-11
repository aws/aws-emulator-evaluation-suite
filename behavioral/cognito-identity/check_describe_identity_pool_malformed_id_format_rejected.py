"""describe-identity-pool-malformed-id-format-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-identity-pool-malformed-id-format-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeIdentityPool rejects an IdentityPoolId that doesn't match the
    region:guid format as ValidationException -- distinct from a well-formed but
    nonexistent pool id, which is ResourceNotFoundException."""
    cip = ctx.client("cognito-identity")
    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    # Positive control.
    described = cip.describe_identity_pool(IdentityPoolId=pool_id)
    assert described["IdentityPoolName"] == pool_name, (
        f"expected positive control to describe {pool_name!r}, got {described!r}"
    )

    # Break exactly one thing: the pool id's syntax (no region:guid separator at all).
    malformed_id = "this-id-has-no-region-guid-separator"
    err = _error(lambda: cip.describe_identity_pool(IdentityPoolId=malformed_id))
    expected = (
        "ValidationException",
        f"1 validation error detected: Value '{malformed_id}' at 'identityPoolId' failed to satisfy"
        " constraint: Member must satisfy regular expression pattern: [\\w-]+:[0-9a-f-]+",
    )
    assert err == expected, (
        f"expected {expected} for malformed IdentityPoolId {malformed_id!r}, got {err!r}"
    )

    # Distinct case: a well-formed but nonexistent pool id -> a different error class.
    nonexistent_id = f"{ctx.region}:ffffffff-ffff-ffff-ffff-ffffffffffff"
    err2 = _error(lambda: cip.describe_identity_pool(IdentityPoolId=nonexistent_id))
    expected2 = ("ResourceNotFoundException", f"IdentityPool '{nonexistent_id}' not found.")
    assert err2 == expected2, (
        f"expected {expected2} for nonexistent IdentityPoolId {nonexistent_id!r}, got {err2!r}"
    )


def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
