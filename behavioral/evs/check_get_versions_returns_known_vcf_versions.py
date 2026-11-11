"""get-versions-returns-known-vcf-versions."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "get-versions-returns-known-vcf-versions"
GROUP = "control-plane"
SERVICES = ["evs"]

_VCF_VERSION_RE = re.compile(r"^(VCF-\d+\.\d+\.\d+|SELF_DEPLOYED)$")
_ESX_VERSION_RE = re.compile(r"^ESXi-")
_VALID_STATUSES = {"AVAILABLE", "RESTRICTED"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVersions returns the documented VCF versions and a non-empty set of
    EC2 instance type / ESX version combinations that Amazon EVS provides, and
    the two collections must be internally consistent with each other."""
    evs = ctx.client("evs")
    resp = evs.get_versions()
    vcf_versions = resp["vcfVersions"]
    instance_type_esx_versions = resp["instanceTypeEsxVersions"]

    assert vcf_versions, "GetVersions returned an empty vcfVersions list"
    assert instance_type_esx_versions, (
        "GetVersions returned an empty instanceTypeEsxVersions list"
    )
    assert all(
        isinstance(i, dict) and i.get("instanceType") and i.get("esxVersions")
        for i in instance_type_esx_versions
    ), f"instanceTypeEsxVersions entry missing instanceType/esxVersions: {instance_type_esx_versions!r}"
    for i in instance_type_esx_versions:
        assert all(_ESX_VERSION_RE.match(e) for e in i["esxVersions"]), (
            f"{i['instanceType']} esxVersions do not look like ESXi build ids: {i['esxVersions']!r}"
        )

    known_instance_types = {i["instanceType"] for i in instance_type_esx_versions}
    esx_versions_by_instance_type = {
        i["instanceType"]: i["esxVersions"] for i in instance_type_esx_versions
    }

    seen_vcf_versions = set()
    for v in vcf_versions:
        assert isinstance(v, dict), f"vcfVersions entry is not an object: {v!r}"
        version = v.get("vcfVersion")
        assert version and _VCF_VERSION_RE.match(version), (
            f"vcfVersion {version!r} is not one of the documented "
            f"VCF-<major>.<minor>.<patch> / SELF_DEPLOYED forms"
        )
        seen_vcf_versions.add(version)

        status = v.get("status")
        assert status in _VALID_STATUSES, (
            f"status {status!r} for vcfVersion {version} is not one of {sorted(_VALID_STATUSES)}"
        )

        default_esx = v.get("defaultEsxVersion")
        assert default_esx and _ESX_VERSION_RE.match(default_esx), (
            f"defaultEsxVersion {default_esx!r} for vcfVersion {version} does not look like an ESXi build id"
        )

        instance_types = v.get("instanceTypes")
        assert instance_types, f"vcfVersion {version} declares no instanceTypes"
        assert set(instance_types) <= known_instance_types, (
            f"vcfVersion {version} names instance types {instance_types} not present in "
            f"instanceTypeEsxVersions {sorted(known_instance_types)}"
        )
        for instance_type in instance_types:
            assert default_esx in esx_versions_by_instance_type[instance_type], (
                f"defaultEsxVersion {default_esx!r} for vcfVersion {version}/{instance_type} is not "
                f"among its own esxVersions {esx_versions_by_instance_type[instance_type]!r}"
            )

    assert "SELF_DEPLOYED" in seen_vcf_versions, (
        f"SELF_DEPLOYED mode is missing from vcfVersions: {sorted(seen_vcf_versions)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
