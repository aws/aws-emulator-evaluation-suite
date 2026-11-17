"""cloudwatch-observability-recommended-policy-resolves-in-iam."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "cloudwatch-observability-recommended-policy-resolves-in-iam"
GROUP = "addon-pod-identity"
SERVICES = ["eks", "iam"]

_ADDON = "amazon-cloudwatch-observability"
_SERVICE_ACCOUNT = "cloudwatch-agent"
#: What the CloudWatch agent the add-on deploys actually writes: metrics, log groups/streams and
#: X-Ray trace segments.
_AGENT_NEEDS = {"cloudwatch:PutMetricData", "logs:PutLogEvents", "logs:CreateLogGroup",
                "xray:PutTraceSegments"}


@tags("axis:happy-path", "concern:representation", "plane:control", "cap:c5")
def run(ctx) -> None:
    """The managed policy EKS's add-on catalog recommends for the CloudWatch Observability
    add-on's pod identity resolves in IAM as an attachable policy and grants the agent's metric,
    log and trace actions.
    """
    eks = ctx.client("eks")
    recs = _recommended_policies(eks)
    assert sorted(recs) == [_SERVICE_ACCOUNT], (
        f"podIdentityConfiguration names service accounts {sorted(recs)!r}, expected only "
        f"{_SERVICE_ACCOUNT!r}"
    )
    arns = recs[_SERVICE_ACCOUNT]
    assert len(arns) == 1 and arns[0].startswith("arn:aws:iam::aws:policy/"), (
        f"{_SERVICE_ACCOUNT} recommends {arns!r}, expected exactly one AWS-managed policy ARN"
    )
    arn = arns[0]
    assert arn == "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy", (
        f"the agent's recommended policy ARN is {arn!r}"
    )

    iam = ctx.client("iam")
    pol = iam.get_policy(PolicyArn=arn)["Policy"]
    assert pol["Arn"] == arn, f"get_policy({arn!r}) answered for {pol['Arn']!r}"
    assert pol["IsAttachable"] is True, f"{arn} is not attachable"

    doc = iam.get_policy_version(PolicyArn=arn, VersionId=pol["DefaultVersionId"])["PolicyVersion"]
    assert doc["IsDefaultVersion"] is True, f"version {doc['VersionId']} is not the default"
    granted: set[str] = set()
    for st in doc["Document"]["Statement"]:
        assert st["Effect"] == "Allow", f"unexpected {st['Effect']} statement {st!r}"
        acts = st["Action"]
        granted |= {acts} if isinstance(acts, str) else set(acts)
    missing = _AGENT_NEEDS - granted
    assert not missing, f"{arn} does not grant {sorted(missing)!r}"


def _recommended_policies(eks) -> dict[str, list[str]]:
    """Which managed policies the add-on catalog recommends per Kubernetes service account, read
    off the add-on build EKS treats as default for the account's default Kubernetes release."""
    release = eks.describe_cluster_versions(defaultOnly=True)["clusterVersions"][0]["clusterVersion"]
    listing = eks.describe_addon_versions(addonName=_ADDON, kubernetesVersion=release)["addons"]
    assert len(listing) == 1, f"DescribeAddonVersions named {len(listing)} add-ons {_ADDON!r}"
    build = [
        v["addonVersion"] for v in listing[0]["addonVersions"]
        for compat in v.get("compatibilities") or []
        if compat.get("clusterVersion") == release and compat.get("defaultVersion") is True
    ]
    assert len(build) == 1, f"{release} marks {len(build)} build(s) of {_ADDON} as default"
    schema = eks.describe_addon_configuration(addonName=_ADDON, addonVersion=build[0])
    service_accounts = schema.get("podIdentityConfiguration") or []
    return {sa["serviceAccount"]: list(sa.get("recommendedManagedPolicies") or [])
            for sa in service_accounts}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
