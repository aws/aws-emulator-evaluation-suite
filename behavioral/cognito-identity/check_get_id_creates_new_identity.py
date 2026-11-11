"""get-id-creates-new-identity."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "get-id-creates-new-identity"
GROUP = "identity-lifecycle"
SERVICES = ["cognito-identity"]

_IDENTITY_ID_RE = re.compile(r"^[\w-]+:[0-9a-f-]+$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetId mints a fresh IdentityId in REGION:GUID form; DescribeIdentity then reports it with no Logins."""
    ci = ctx.client("cognito-identity")
    name = ctx.unique_name("sim2real-behav-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(
        lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id])
    )

    assert _IDENTITY_ID_RE.match(identity_id), f"malformed IdentityId: {identity_id!r}"
    assert identity_id.split(":", 1)[0] == ctx.region, (
        f"expected IdentityId region prefix {ctx.region!r}, got {identity_id.split(':', 1)[0]!r} in {identity_id!r}"
    )

    described = ci.describe_identity(IdentityId=identity_id)
    assert described["IdentityId"] == identity_id, (
        f"DescribeIdentity returned {described['IdentityId']!r}, expected {identity_id!r}"
    )
    assert described.get("Logins", []) == [], (
        f"expected no Logins on a freshly created identity, got {described.get('Logins')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
