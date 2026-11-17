"""ebs-csi-driver-recommended-policy-resolves-in-iam."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "ebs-csi-driver-recommended-policy-resolves-in-iam"
GROUP = "addon-pod-identity"
SERVICES = ["eks", "iam"]

_ADDON = "aws-ebs-csi-driver"
_SERVICE_ACCOUNT = "ebs-csi-controller-sa"
#: The EBS volume lifecycle calls the controller makes once a pod requests a PersistentVolume.
_CONTROLLER_NEEDS = {
    "ec2:CreateVolume",
    "ec2:DeleteVolume",
    "ec2:AttachVolume",
    "ec2:DetachVolume",
    "ec2:CreateSnapshot",
    "ec2:DeleteSnapshot",
}


@tags("axis:happy-path", "concern:representation", "plane:control", "cap:c5")
def run(ctx) -> None:
    """The managed policy EKS's add-on catalog recommends for the EBS CSI driver's pod identity
    resolves in IAM as an attachable policy at the root path, not the legacy service-role path,
    and grants the EBS volume actions the controller performs.
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
    assert arn == "arn:aws:iam::aws:policy/AmazonEBSCSIDriverPolicyV2", (
        f"the controller's recommended policy ARN is {arn!r}"
    )

    iam = ctx.client("iam")
    pol = iam.get_policy(PolicyArn=arn)["Policy"]
    assert pol["Arn"] == arn, f"get_policy({arn!r}) answered for {pol['Arn']!r}"
    assert pol["IsAttachable"] is True, f"{arn} is not attachable"
    assert pol["Path"] == "/", f"{arn} sits at path {pol['Path']!r}, expected the root path"

    doc = iam.get_policy_version(PolicyArn=arn, VersionId=pol["DefaultVersionId"])["PolicyVersion"]
    assert doc["IsDefaultVersion"] is True, f"version {doc['VersionId']} is not the default"
    granted: set[str] = set()
    for st in doc["Document"]["Statement"]:
        assert st["Effect"] == "Allow", f"unexpected {st['Effect']} statement {st!r}"
        acts = st["Action"]
        granted |= {acts} if isinstance(acts, str) else set(acts)
    missing = _CONTROLLER_NEEDS - granted
    assert not missing, f"{arn} does not grant {sorted(missing)!r}"


def _recommended_policies(eks) -> dict[str, list[str]]:
    """The add-on's podIdentityConfiguration, keyed by Kubernetes service account, for whichever
    add-on version EKS marks default on the account's default Kubernetes release."""
    release = eks.describe_cluster_versions(defaultOnly=True)["clusterVersions"][0]["clusterVersion"]
    catalog_entry = eks.describe_addon_versions(addonName=_ADDON, kubernetesVersion=release)["addons"]
    assert len(catalog_entry) == 1, (
        f"the add-on catalog has {len(catalog_entry)} entries named {_ADDON!r}, expected one"
    )
    default_versions = [
        version["addonVersion"] for version in catalog_entry[0]["addonVersions"]
        for compat in version.get("compatibilities") or []
        if compat.get("clusterVersion") == release and compat.get("defaultVersion") is True
    ]
    assert len(default_versions) == 1, (
        f"{release} has {len(default_versions)} default build(s) of {_ADDON}, expected one"
    )
    schema = eks.describe_addon_configuration(addonName=_ADDON, addonVersion=default_versions[0])
    accounts = schema.get("podIdentityConfiguration") or []
    return {a["serviceAccount"]: list(a.get("recommendedManagedPolicies") or []) for a in accounts}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
