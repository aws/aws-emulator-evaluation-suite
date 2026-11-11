"""get-id-unauthenticated-creates-identity."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "get-id-unauthenticated-creates-identity"
GROUP = "state"
SERVICES = ["cognito-identity"]

_ID_RE = re.compile(r"^[\w-]+:[0-9a-f-]+$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetId on an unauthenticated-allowed pool creates a real identity visible via Describe/List."""
    ci = ctx.client("cognito-identity")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"env": "sim2real-test", "owner": "behavioral-suite"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert _ID_RE.match(identity_id), f"unexpected identity id format: {identity_id}"
    assert identity_id.split(":")[0] == pool_id.split(":")[0], "identity id region prefix mismatch"

    described = ci.describe_identity(IdentityId=identity_id)
    assert described["IdentityId"] == identity_id, (
        f"DescribeIdentity returned {described['IdentityId']!r}, expected {identity_id!r}"
    )
    assert described.get("Logins", []) == [], (
        f"expected no Logins on a freshly created unauthenticated identity, got {described.get('Logins')!r}"
    )
    assert "CreationDate" in described, f"expected CreationDate in DescribeIdentity response, got keys {sorted(described)}"

    listed = ci.list_identities(IdentityPoolId=pool_id, MaxResults=60)
    listed_ids = {i["IdentityId"] for i in listed.get("Identities", [])}
    assert identity_id in listed_ids, "newly created identity missing from ListIdentities"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
