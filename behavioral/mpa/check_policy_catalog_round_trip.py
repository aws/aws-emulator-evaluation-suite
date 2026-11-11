"""policy-catalog-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "policy-catalog-round-trip"
GROUP = "state"
SERVICES = ["mpa"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPolicies, ListPolicyVersions and GetPolicyVersion agree on the built-in managed policy
    catalog: the default version matches the IsDefault version, and GetPolicyVersion returns its
    document.
    """
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")
    policies = mpa.list_policies(MaxResults=20)["Policies"]
    assert len(policies) > 0, "account has no MPA managed policies"
    policy = policies[0]

    versions = mpa.list_policy_versions(PolicyArn=policy["Arn"], MaxResults=20)[
        "PolicyVersions"
    ]
    assert len(versions) > 0, f"policy {policy['Arn']} has no versions"
    default_version = next(
        (v for v in versions if v["VersionId"] == policy["DefaultVersion"]), None
    )
    assert default_version is not None, (
        f"ListPolicies default version {policy['DefaultVersion']!r} for {policy['Arn']} "
        f"not present among ListPolicyVersions results "
        f"{[v['VersionId'] for v in versions]}"
    )
    assert default_version["PolicyArn"] == policy["Arn"], (
        f"expected PolicyArn {policy['Arn']!r}, got {default_version['PolicyArn']!r}"
    )
    assert default_version["IsDefault"] is True, (
        f"version {default_version['VersionId']!r} matches the policy's DefaultVersion but "
        f"IsDefault={default_version['IsDefault']!r}"
    )

    version_arn = default_version["Arn"]
    full = mpa.get_policy_version(PolicyVersionArn=version_arn)["PolicyVersion"]
    assert full["Arn"] == version_arn, f"expected Arn {version_arn!r}, got {full['Arn']!r}"
    assert full["PolicyArn"] == policy["Arn"], (
        f"expected PolicyArn {policy['Arn']!r}, got {full['PolicyArn']!r}"
    )
    assert full["Name"] == policy["Name"], (
        f"expected Name {policy['Name']!r}, got {full['Name']!r}"
    )
    assert full["PolicyType"] == policy["PolicyType"], (
        f"expected PolicyType {policy['PolicyType']!r}, got {full['PolicyType']!r}"
    )
    assert isinstance(full["Document"], str) and len(full["Document"]) > 0, (
        f"expected a non-empty Document string, got {full['Document']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
