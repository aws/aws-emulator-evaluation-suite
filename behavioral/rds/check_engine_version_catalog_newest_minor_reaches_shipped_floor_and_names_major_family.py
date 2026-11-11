"""engine-version-catalog-newest-minor-reaches-shipped-floor-and-names-major-family."""

from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "engine-version-catalog-newest-minor-reaches-shipped-floor-and-names-major-family"
GROUP = "engine_versions"
SERVICES = ["rds"]

#: (Engine, major, minor floor): the newest listed <major>.<minor> is at least the floor, a minor
#: AWS has offered for well over a year; newer minors only raise the newest one.
_MAJORS = (
    ("postgres", 16, 8),
    ("aurora-postgresql", 15, 10),
)


def _minors(rds, engine, major):
    """The <major>.<minor> versions DescribeDBEngineVersions lists for an engine, as ints."""
    found = []
    for page in rds.get_paginator("describe_db_engine_versions").paginate(Engine=engine):
        for v in page["DBEngineVersions"]:
            m = re.fullmatch(rf"{major}\.(\d+)", v["EngineVersion"])
            if m:
                found.append(int(m.group(1)))
    return found


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBEngineVersions lists postgres 16 and aurora-postgresql 15 minors at or past a
    long-shipped floor, and a lookup of the newest returns that one version with its major's family.
    """
    rds = ctx.client("rds")
    for engine, major, floor in _MAJORS:
        minors = _minors(rds, engine, major)
        assert minors and max(minors) >= floor, (
            f"DescribeDBEngineVersions(Engine={engine!r}) must list a {major}.x minor at or past "
            f"{major}.{floor}; listed {major}.x minors: {sorted(minors)!r}"
        )
        newest = f"{major}.{max(minors)}"
        listed = rds.describe_db_engine_versions(Engine=engine, EngineVersion=newest)[
            "DBEngineVersions"
        ]
        got = [(v["Engine"], v["EngineVersion"], v["DBParameterGroupFamily"]) for v in listed]
        want = [(engine, newest, f"{engine}{major}")]
        assert got == want, (
            f"DescribeDBEngineVersions(Engine={engine!r}, EngineVersion={newest!r}) must list "
            f"exactly {want!r}; got {got!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
