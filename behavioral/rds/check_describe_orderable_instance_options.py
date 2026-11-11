"""describe-orderable-instance-options."""
from __future__ import annotations

import re

from behavioral_harness import tags


CHECK = "describe-orderable-instance-options"
GROUP = 'engine_versions'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeOrderableDBInstanceOptions honors MaxRecords, the Engine and DBInstanceClass filters.

    Each db.t3.micro option lists zones of the caller's region, and gp2 is among its storage types.
    """
    rds = ctx.client("rds")
    resp = rds.describe_orderable_db_instance_options(Engine="mysql", MaxRecords=20)
    options = resp["OrderableDBInstanceOptions"]
    assert 1 <= len(options) <= 20, (
        f"expected 1..MaxRecords(20) options for mysql, got {len(options)}"
    )
    for opt in options:
        assert opt["Engine"] == "mysql", f"expected engine mysql, got {opt['Engine']!r}"
        assert opt["DBInstanceClass"], f"empty DBInstanceClass in {opt!r}"
    if len(options) == 20:
        assert resp.get("Marker"), (
            "a full page (MaxRecords=20) with no Marker claims mysql's orderable "
            "catalog is exactly 20 options wide, which is not the real catalog shape"
        )

    paginator = rds.get_paginator("describe_orderable_db_instance_options")
    by_class = [
        opt
        for page in paginator.paginate(Engine="mysql", DBInstanceClass="db.t3.micro")
        for opt in page["OrderableDBInstanceOptions"]
    ]
    assert by_class, "db.t3.micro is orderable for mysql, but the class filter returned nothing"
    zone_name = re.compile(re.escape(ctx.region) + r"[a-z]")
    for opt in by_class:
        assert opt["Engine"] == "mysql", f"class-filtered option has engine {opt['Engine']!r}"
        assert opt["DBInstanceClass"] == "db.t3.micro", (
            f"class filter db.t3.micro returned class {opt['DBInstanceClass']!r}"
        )
        zones = [az["Name"] for az in opt["AvailabilityZones"]]
        assert zones, f"option {opt['EngineVersion']!r} lists no availability zones"
        stray = [z for z in zones if not zone_name.fullmatch(z)]
        assert not stray, (
            f"option {opt['EngineVersion']!r} lists zones outside {ctx.region}: {stray!r}"
        )
    storage_types = {opt["StorageType"] for opt in by_class}
    assert "gp2" in storage_types, (
        f"mysql db.t3.micro offers no gp2 storage, storage types were {sorted(storage_types)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
