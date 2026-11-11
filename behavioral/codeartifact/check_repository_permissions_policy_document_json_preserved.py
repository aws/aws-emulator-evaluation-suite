"""repository-permissions-policy-document-json-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "repository-permissions-policy-document-json-preserved"
GROUP = "server-side"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRepositoryPermissionsPolicy returns the document PutRepositoryPermissionsPolicy stored as an
    equal parsed JSON value (CodeArtifact reorders fields, so the text itself is not compared)."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-carepopolj-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    repo = ctx.unique_name("repo-")
    ca.create_repository(
        domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "codeartifact:DescribeRepository",
                "Resource": "*",
            }
        ],
    }
    policy_text = json.dumps(policy_doc, separators=(",", ":"), sort_keys=True)

    ca.put_repository_permissions_policy(
        domain=domain, repository=repo, policyDocument=policy_text
    )
    ctx.on_cleanup(
        lambda: ca.delete_repository_permissions_policy(domain=domain, repository=repo)
    )

    fetched = ca.get_repository_permissions_policy(domain=domain, repository=repo)["policy"][
        "document"
    ]
    assert json.loads(fetched) == policy_doc, (
        f"policy document value was altered: {fetched!r} != {policy_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
