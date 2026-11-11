"""list-supported-instance-types-for-release-label."""
from __future__ import annotations

from behavioral_harness import tags

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"

CHECK = "list-supported-instance-types-for-release-label"
GROUP = 'release-labels'
SERVICES = ['emr']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSupportedInstanceTypes describes the instance catalogue for a release label."""
    emr = ctx.client("emr")
    # ListSupportedInstanceTypes documents no order or page size, so m5.xlarge may sit on a later
    # page; the whole catalogue is read before grading it.
    resp = emr.list_supported_instance_types(ReleaseLabel=RELEASE_LABEL)
    types = list(resp["SupportedInstanceTypes"])
    while resp.get("Marker"):
        resp = emr.list_supported_instance_types(ReleaseLabel=RELEASE_LABEL, Marker=resp["Marker"])
        types.extend(resp["SupportedInstanceTypes"])
    assert types, "ListSupportedInstanceTypes returned nothing for a valid release label"

    by_type = {t["Type"]: t for t in types}
    assert INSTANCE_TYPE in by_type, (
        f"{INSTANCE_TYPE} must be supported on {RELEASE_LABEL}, got {sorted(by_type)[:8]}"
    )
    entry = by_type[INSTANCE_TYPE]
    # m5.xlarge is EC2's own published hardware (4 vCPU / 16 GiB); a synthesised
    # catalogue that merely reports "some positive number" cannot be told apart
    # from the real one, so pin the real figures rather than just their sign.
    # EMR reports memory available to EMR, which is <= the raw instance memory.
    assert entry.get("VCPU") == 4, f"m5.xlarge has 4 vCPUs, catalogue reports {entry.get('VCPU')!r}"
    assert 12.0 <= entry.get("MemoryGB", 0) <= 16.0, (
        f"m5.xlarge MemoryGB must be a real figure at or just under 16 GiB, "
        f"got {entry.get('MemoryGB')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
