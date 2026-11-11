"""list-aws-managed-policies-includes-well-known-policies."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-aws-managed-policies-includes-well-known-policies"
GROUP = "managed_policies"
SERVICES = ["iam"]

_EXPECTED_NAMES = {"AdministratorAccess", "ReadOnlyAccess", "AWSLambdaBasicExecutionRole"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPolicies(Scope=AWS), paginated to exhaustion, repeats no policy across pages and
    includes a few well-known policies, each under its AWS-owned ARN; catalog size is not graded.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html
    """
    iam = ctx.client("iam")
    paginator = iam.get_paginator("list_policies")

    arns = []
    by_name = {}
    for page in paginator.paginate(Scope="AWS"):
        for policy in page["Policies"]:
            arns.append(policy["Arn"])
            by_name[policy["PolicyName"]] = policy["Arn"]

    repeated = sorted({a for a in arns if arns.count(a) > 1})
    assert not repeated, f"pagination returned {len(repeated)} policies twice: {repeated[:10]!r}"
    missing = _EXPECTED_NAMES - set(by_name)
    assert not missing, f"expected catalog to include {_EXPECTED_NAMES}, missing {missing}"
    for name in sorted(_EXPECTED_NAMES):
        arn = by_name[name]
        assert arn.startswith("arn:aws:iam::aws:policy/") and arn.endswith("/" + name), (
            f"{name} is listed under {arn!r}, not an AWS-owned policy ARN"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
