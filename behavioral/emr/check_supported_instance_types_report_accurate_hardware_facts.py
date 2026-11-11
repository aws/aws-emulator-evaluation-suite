"""supported-instance-types-report-accurate-hardware-facts."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "supported-instance-types-report-accurate-hardware-facts"
GROUP = 'release-labels'
SERVICES = ['emr']

# EC2-published hardware facts. MemoryGB is what EMR makes available (<= raw memory), so it is
# asserted as a bounded range. InstanceFamilyId is a workload-class x generation category
# (e.g. GENERAL_CURRENT_GEN), not the `m5` prefix.
EXPECTED_FACTS = {
    # type: (vcpu, raw_memory_gib, instance_family_id)
    "m5.xlarge": (4, 16.0, "GENERAL_CURRENT_GEN"),
    "m5.2xlarge": (8, 32.0, "GENERAL_CURRENT_GEN"),
    "c5.xlarge": (4, 8.0, "COMPUTE_CURRENT_GEN"),
}

# InstanceFamilyId values: five workload classes crossed with CURRENT/PREVIOUS generation.
INSTANCE_FAMILY_IDS = {
    f"{workload}_{generation}_GEN"
    for workload in ("GENERAL", "COMPUTE", "HI_MEM", "STORAGE", "GPU")
    for generation in ("CURRENT", "PREVIOUS")
}


def _list_supported_instance_types(emr, release_label):
    """Every SupportedInstanceType for release_label, following Marker to the end."""
    out = []
    marker = None
    for _ in range(50):  # bounded: the catalogue is a few hundred entries
        kwargs = {"ReleaseLabel": release_label}
        if marker:
            kwargs["Marker"] = marker
        resp = emr.list_supported_instance_types(**kwargs)
        out.extend(resp.get("SupportedInstanceTypes", []))
        marker = resp.get("Marker")
        if not marker:
            return out
    raise AssertionError(
        f"ListSupportedInstanceTypes for {release_label} did not terminate in 50 pages "
        f"({len(out)} entries so far) — the Marker protocol is looping"
    )


def _release_labels(emr, prefix):
    """Release labels matching prefix, newest-first as EMR returns them."""
    out = []
    token = None
    for _ in range(50):
        kwargs = {"Filters": {"Prefix": prefix}}
        if token:
            kwargs["NextToken"] = token
        resp = emr.list_release_labels(**kwargs)
        out.extend(resp.get("ReleaseLabels", []))
        token = resp.get("NextToken")
        if not token:
            return out
    raise AssertionError(f"ListReleaseLabels for prefix {prefix!r} did not terminate in 50 pages")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The EMR instance catalogue reports EC2's real vCPU/memory/family facts, is internally
    consistent, and differs between the emr-6 and emr-7 release lines (catalogue and Spark version).

    Reference: https://docs.aws.amazon.com/emr/latest/APIReference/API_SupportedInstanceType.html
    """
    emr = ctx.client("emr")

    six = _release_labels(emr, "emr-6.")
    seven = _release_labels(emr, "emr-7.")
    assert six, "ListReleaseLabels returned no emr-6.x labels"
    assert seven, "ListReleaseLabels returned no emr-7.x labels"
    # ListReleaseLabels is newest-first, so [0] is the newest label in each line.
    six_label, seven_label = six[0], seven[0]

    catalogue = _list_supported_instance_types(emr, six_label)
    assert len(catalogue) >= 20, (
        f"{six_label} must support a real instance catalogue (dozens of types), got "
        f"{len(catalogue)}: {[c.get('Type') for c in catalogue]!r}"
    )
    by_type = {c["Type"]: c for c in catalogue}
    assert len(by_type) == len(catalogue), (
        f"the catalogue for {six_label} repeats instance types: "
        f"{len(catalogue)} entries, {len(by_type)} distinct"
    )

    for itype, (vcpu, raw_mem_gib, family_id) in EXPECTED_FACTS.items():
        entry = by_type.get(itype)
        assert entry is not None, (
            f"{six_label} must support {itype}; catalogue has "
            f"{sorted(by_type)[:20]!r}..."
        )
        assert entry["VCPU"] == vcpu, (
            f"{itype} has {vcpu} vCPUs; catalogue reports {entry['VCPU']!r}"
        )
        # EMR reports memory available to EMR: below the raw figure, but not by much.
        assert raw_mem_gib * 0.75 <= entry["MemoryGB"] <= raw_mem_gib, (
            f"{itype} MemoryGB must be a real figure at or just under the "
            f"{raw_mem_gib} GiB the instance has; got {entry['MemoryGB']!r}"
        )
        assert entry["InstanceFamilyId"] == family_id, (
            f"{itype} belongs to EMR instance family {family_id!r}; catalogue reports "
            f"{entry['InstanceFamilyId']!r}"
        )
        assert entry["Architecture"] == "X86_64", (
            f"{itype} is an x86 instance type; catalogue reports "
            f"{entry['Architecture']!r}"
        )

    # m5 is EBS-only, so its instance-store fields are zeroed, not absent.
    m5 = by_type["m5.xlarge"]
    assert m5["EbsStorageOnly"] is True, (
        f"m5.xlarge is EBS-only; catalogue reports EbsStorageOnly={m5['EbsStorageOnly']!r}"
    )
    assert m5["StorageGB"] == 0, (
        f"an EBS-only type must report StorageGB 0, got {m5['StorageGB']!r}"
    )
    assert m5["NumberOfDisks"] == 0, (
        f"an EBS-only type must report NumberOfDisks 0, got {m5['NumberOfDisks']!r}"
    )
    assert m5["EbsOptimizedAvailable"] is True, (
        f"m5.xlarge supports EBS optimization; got "
        f"{m5['EbsOptimizedAvailable']!r}"
    )

    # InstanceFamilyId is a property of the EC2 family, never of the size.
    family_id_of: dict[str, str] = {}
    for entry in catalogue:
        itype = entry["Type"]
        assert "." in itype, f"instance type must be family.size, got {itype!r}"
        ec2_family = itype.split(".")[0]
        assert entry["InstanceFamilyId"] in INSTANCE_FAMILY_IDS, (
            f"{itype} reports an unmodelled InstanceFamilyId "
            f"{entry['InstanceFamilyId']!r}; EMR uses one of {sorted(INSTANCE_FAMILY_IDS)}"
        )
        seen = family_id_of.setdefault(ec2_family, entry["InstanceFamilyId"])
        assert seen == entry["InstanceFamilyId"], (
            f"InstanceFamilyId is a property of the EC2 family, not the size: {itype} "
            f"reports {entry['InstanceFamilyId']!r} but another {ec2_family}.* entry "
            f"reports {seen!r}"
        )
        assert entry["VCPU"] >= 1, f"{itype} must report at least 1 vCPU, got {entry['VCPU']!r}"
        assert entry["MemoryGB"] > 0, (
            f"{itype} must report non-zero MemoryGB, got {entry['MemoryGB']!r}"
        )
        assert entry["Architecture"] in {"X86_64", "AARCH64"}, (
            f"{itype} reports an unmodelled Architecture {entry['Architecture']!r}"
        )
        if entry["EbsStorageOnly"]:
            assert entry["StorageGB"] == 0 and entry["NumberOfDisks"] == 0, (
                f"EBS-only {itype} must zero its instance-store fields, got "
                f"StorageGB={entry['StorageGB']!r} NumberOfDisks={entry['NumberOfDisks']!r}"
            )
        else:
            assert entry["NumberOfDisks"] >= 1, (
                f"instance-store type {itype} must report at least one disk, got "
                f"{entry['NumberOfDisks']!r}"
            )

    # All five workload classes appear across the catalogue.
    workload_classes = {fid.rsplit("_", 2)[0] for fid in family_id_of.values()}
    assert workload_classes == {"GENERAL", "COMPUTE", "HI_MEM", "STORAGE", "GPU"}, (
        f"the {six_label} catalogue must span all five EMR workload classes, got "
        f"{sorted(workload_classes)!r}"
    )

    # Graviton support is real: some supported types are AARCH64, not all X86_64.
    arches = {e["Architecture"] for e in catalogue}
    assert arches == {"X86_64", "AARCH64"}, (
        f"the {six_label} catalogue must span both x86 and Graviton instance types, "
        f"got {arches!r}"
    )

    seven_catalogue = {c["Type"] for c in _list_supported_instance_types(emr, seven_label)}
    six_types = set(by_type)
    assert seven_catalogue, f"{seven_label} returned an empty catalogue"
    assert seven_catalogue != six_types, (
        f"{six_label} and {seven_label} returned an identical instance catalogue "
        f"({len(six_types)} types) — the ReleaseLabel argument is being ignored"
    )

    six_apps = {
        a["Name"]: a.get("Version")
        for a in emr.describe_release_label(ReleaseLabel=six_label)["Applications"]
    }
    seven_apps = {
        a["Name"]: a.get("Version")
        for a in emr.describe_release_label(ReleaseLabel=seven_label)["Applications"]
    }
    assert "Spark" in six_apps and "Spark" in seven_apps, (
        f"both release lines must ship Spark; got {sorted(six_apps)!r} / "
        f"{sorted(seven_apps)!r}"
    )
    assert six_apps["Spark"] and seven_apps["Spark"], (
        f"Spark must carry a Version in both lines, got {six_apps['Spark']!r} / "
        f"{seven_apps['Spark']!r}"
    )
    assert six_apps["Spark"] != seven_apps["Spark"], (
        f"{six_label} and {seven_label} must ship different Spark versions, both "
        f"report {six_apps['Spark']!r} — the release inventory is static"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
