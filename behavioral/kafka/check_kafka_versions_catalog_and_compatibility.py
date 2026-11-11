"""kafka-versions-catalog-and-compatibility."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "kafka-versions-catalog-and-compatibility"
GROUP = 'kafka-versions'
SERVICES = ['kafka']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListKafkaVersions returns versions that each carry a status and include 3.6.0, and account-wide
    GetCompatibleKafkaVersions returns rows whose upgrade targets are all listed versions."""
    msk = ctx.client("kafka")
    versions = []
    next_token = None
    for _ in range(20):
        kwargs = {}
        if next_token:
            kwargs["NextToken"] = next_token
        page = msk.list_kafka_versions(**kwargs)
        versions.extend(page.get("KafkaVersions", []))
        next_token = page.get("NextToken")
        if not next_token:
            break

    assert versions, "ListKafkaVersions returned no versions"
    names = {v["Version"] for v in versions}
    assert all(v.get("Status") for v in versions), versions
    assert "3.6.0" in names, sorted(names)

    compat = msk.get_compatible_kafka_versions()["CompatibleKafkaVersions"]
    assert compat, "GetCompatibleKafkaVersions returned nothing"
    for entry in compat:
        assert entry.get("SourceVersion"), entry
        assert isinstance(entry.get("TargetVersions"), list), entry
    # At least one source version must actually have an upgrade path, and every
    # advertised target must itself be a real, listed version.
    upgradable = [e for e in compat if e["TargetVersions"]]
    assert upgradable, compat
    for entry in upgradable:
        unknown = [t for t in entry["TargetVersions"] if t not in names]
        assert not unknown, f"upgrade targets absent from ListKafkaVersions: {unknown}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
