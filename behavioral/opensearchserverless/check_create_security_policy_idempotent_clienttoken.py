"""create-security-policy-idempotent-clienttoken."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "create-security-policy-idempotent-clienttoken"
GROUP = "ordering"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated CreateSecurityPolicy calls with an identical clientToken dedupe to one policy."""
    client = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-sp-")
    token = str(uuid.uuid4())
    policy_doc = json.dumps(
        {
            "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{name}"]}],
            "AWSOwnedKey": True,
        }
    )

    resp1 = client.create_security_policy(
        type="encryption", name=name, policy=policy_doc, clientToken=token
    )
    detail1 = resp1["securityPolicyDetail"]
    ctx.on_cleanup(lambda: client.delete_security_policy(type="encryption", name=name))

    resp2 = client.create_security_policy(
        type="encryption", name=name, policy=policy_doc, clientToken=token
    )
    detail2 = resp2["securityPolicyDetail"]

    assert detail2["policyVersion"] == detail1["policyVersion"], (
        "repeating CreateSecurityPolicy with the same clientToken should not mint a new "
        f"policyVersion, got {detail1['policyVersion']!r} then {detail2['policyVersion']!r}"
    )
    assert detail2["createdDate"] == detail1["createdDate"], (
        "a deduped CreateSecurityPolicy must return the original createdDate, not a "
        f"freshly minted one, got {detail1['createdDate']!r} then {detail2['createdDate']!r}"
    )

    got = client.get_security_policy(type="encryption", name=name)["securityPolicyDetail"]
    assert got["policyVersion"] == detail1["policyVersion"], (
        "the persisted policy should still carry the original version, not a duplicate"
    )
    assert got["createdDate"] == detail1["createdDate"], (
        "the persisted policy should still carry the original createdDate, not a duplicate"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
