"""repository-policy-document-byte-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "repository-policy-document-byte-preserved"
GROUP = "representation"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A repository policy round-trips Set/GetRepositoryPolicy with identical statements, Sids,
    Actions and Principals, except that a numeric Condition value (300) comes back as "300"."""
    ecrpublic = _ecrpublic(ctx)
    repo_name = ctx.unique_name("sim2real-ecrpub-pol-")

    ecrpublic.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: ecrpublic.delete_repository(repositoryName=repo_name, force=True))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPublicPull",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["ecr-public:BatchGetImage", "ecr-public:GetDownloadUrlForLayer"],
            },
            {
                "Sid": "AllowConditionalDescribe",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "ecr-public:DescribeRepositories",
                "Condition": {"NumericLessThanEquals": {"aws:MultiFactorAuthAge": 300}},
            },
        ],
    }

    ecrpublic.set_repository_policy(repositoryName=repo_name, policyText=json.dumps(policy))
    resp = ecrpublic.get_repository_policy(repositoryName=repo_name)
    got = json.loads(resp["policyText"])

    assert got["Version"] == policy["Version"], f"expected Version {policy['Version']!r}, got {got['Version']!r}"
    assert len(got["Statement"]) == len(policy["Statement"]), (
        f"expected {len(policy['Statement'])} statements, got {len(got['Statement'])}: {got['Statement']!r}"
    )

    stmt0 = got["Statement"][0]
    assert stmt0["Sid"] == "AllowPublicPull", f"expected Sid 'AllowPublicPull', got {stmt0.get('Sid')!r}"
    assert stmt0["Effect"] == "Allow", f"expected Effect 'Allow', got {stmt0.get('Effect')!r}"
    assert stmt0["Principal"] == "*", f"expected Principal '*', got {stmt0.get('Principal')!r}"
    assert stmt0["Action"] == ["ecr-public:BatchGetImage", "ecr-public:GetDownloadUrlForLayer"], (
        f"expected Action list preserved in order, got {stmt0.get('Action')!r}"
    )

    stmt1 = got["Statement"][1]
    assert stmt1["Sid"] == "AllowConditionalDescribe", (
        f"expected Sid 'AllowConditionalDescribe', got {stmt1.get('Sid')!r}"
    )
    assert stmt1["Effect"] == "Allow", f"expected Effect 'Allow', got {stmt1.get('Effect')!r}"
    assert stmt1["Action"] == "ecr-public:DescribeRepositories", (
        f"expected Action 'ecr-public:DescribeRepositories', got {stmt1.get('Action')!r}"
    )

    # The policy engine canonicalizes Condition values to strings, even ones written as numbers.
    mfa_age = got["Statement"][1]["Condition"]["NumericLessThanEquals"]["aws:MultiFactorAuthAge"]
    assert mfa_age == "300" and isinstance(mfa_age, str), (
        f"expected AWS to canonicalize the numeric condition value to the string '300', "
        f"got {mfa_age!r} ({type(mfa_age)})"
    )


def _ecrpublic(ctx):
    """An ecr-public client pinned to us-east-1, the only region that serves its API."""
    return ctx.client("ecr-public", region="us-east-1")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
