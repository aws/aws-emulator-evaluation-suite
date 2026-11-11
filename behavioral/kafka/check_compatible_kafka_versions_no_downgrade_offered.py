"""compatible-kafka-versions-no-downgrade-offered."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "compatible-kafka-versions-no-downgrade-offered"
GROUP = 'kafka-versions'
SERVICES = ['kafka']


def _paginate(fn, list_key, **kwargs):
    items, token = [], None
    for _ in range(200):
        page_kwargs = dict(kwargs)
        if token:
            page_kwargs["NextToken"] = token
        resp = fn(**page_kwargs)
        items.extend(resp.get(list_key, []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


def _version_key(version: str):
    """Sortable key for a Kafka version string, tolerant of MSK's suffixed variants.

    MSK advertises plain semantic versions ("3.6.0") and suffixed ones ("2.8.2.tiered",
    "3.6.0.kraft"). Numeric components order the version; a suffix is a variant of the same
    upstream release, so it is compared after the numbers as a plain string.
    """
    numbers, suffix = [], ""
    for part in version.split("."):
        if part.isdigit():
            numbers.append(int(part))
        else:
            suffix = part
            break
    return (tuple(numbers), suffix)


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCompatibleKafkaVersions returns unique rows whose every SourceVersion is a listed Kafka version,
    no version among its own TargetVersions and no target below its source, so the upgrade table never
    offers a downgrade."""
    msk = ctx.client("kafka")

    listed = _paginate(msk.list_kafka_versions, "KafkaVersions")
    assert listed, "ListKafkaVersions returned no versions"
    catalog = {v["Version"] for v in listed}
    # ListKafkaVersions keys a catalog row by the (Version, Status) PAIR, not the version
    # string: a version can be listed twice, once ACTIVE and once DEPRECATED. So the uniqueness invariant is on the pair; a repeated pair
    # is still a duplicated row and still a bug.
    rows = [(v["Version"], v.get("Status")) for v in listed]
    assert len(set(rows)) == len(rows), (
        f"ListKafkaVersions returned duplicate (Version, Status) rows: {sorted(rows)}"
    )

    compat = msk.get_compatible_kafka_versions()["CompatibleKafkaVersions"]
    assert compat, "account-wide GetCompatibleKafkaVersions returned an empty table"

    unlisted_sources = sorted(
        e["SourceVersion"] for e in compat if e["SourceVersion"] not in catalog
    )
    assert not unlisted_sources, (
        f"GetCompatibleKafkaVersions offers upgrade paths from versions ListKafkaVersions "
        f"does not advertise: {unlisted_sources}"
    )

    self_targets = sorted(
        e["SourceVersion"] for e in compat if e["SourceVersion"] in (e.get("TargetVersions") or [])
    )
    assert not self_targets, (
        f"these versions list themselves as an upgrade target: {self_targets}"
    )

    downgrades = []
    for entry in compat:
        source = entry["SourceVersion"]
        for target in entry.get("TargetVersions") or []:
            if _version_key(target) < _version_key(source):
                downgrades.append(f"{source} -> {target}")
    assert not downgrades, (
        f"MSK does not support Kafka downgrades, but the compatibility table offers "
        f"{downgrades}"
    )

    # The table must still be useful, not vacuously consistent by being empty of targets.
    upgradable = [e for e in compat if e.get("TargetVersions")]
    assert upgradable, (
        f"no version in the compatibility table has any upgrade target at all: {compat}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
