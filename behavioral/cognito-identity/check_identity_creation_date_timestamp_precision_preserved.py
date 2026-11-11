"""identity-creation-date-timestamp-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "identity-creation-date-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIdentity's CreationDate is a stable, precise value: repeated reads of
    the same identity return the exact same timestamp rather than a value that drifts
    or gets re-truncated on each call."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    first = ci.describe_identity(IdentityId=identity_id)
    second = ci.describe_identity(IdentityId=identity_id)

    assert first["CreationDate"] == second["CreationDate"], (
        f"CreationDate is unstable across repeated reads: {first['CreationDate']!r} "
        f"!= {second['CreationDate']!r}"
    )
    # boto3 parses the wire timestamp into a datetime; a service that truncates to
    # whole seconds server-side would still be internally consistent (equal on both
    # reads) but a faithful emulator must not vary the fractional part call-to-call.
    assert first["CreationDate"].microsecond == second["CreationDate"].microsecond, (
        f"CreationDate microsecond component drifted across reads: "
        f"{first['CreationDate'].microsecond!r} != {second['CreationDate'].microsecond!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
