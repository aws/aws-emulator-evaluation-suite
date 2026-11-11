"""domain-permissions-policy-document-json-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "domain-permissions-policy-document-json-preserved"
GROUP = "server-side"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDomainPermissionsPolicy returns the document given to PutDomainPermissionsPolicy with the
    same semantic content; CodeArtifact rewrites its key order, so bytes are not compared.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-cadompolj-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "codeartifact:DescribeDomain",
                "Resource": "*",
            }
        ],
    }
    policy_text = json.dumps(policy_doc, separators=(",", ":"), sort_keys=True)

    ca.put_domain_permissions_policy(domain=domain, policyDocument=policy_text)
    ctx.on_cleanup(lambda: ca.delete_domain_permissions_policy(domain=domain))

    fetched = ca.get_domain_permissions_policy(domain=domain)["policy"]["document"]
    assert json.loads(fetched) == json.loads(
        policy_text
    ), f"policy document was altered: {fetched!r} != {policy_text!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
