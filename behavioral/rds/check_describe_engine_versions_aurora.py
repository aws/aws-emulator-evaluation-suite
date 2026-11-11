"""describe-engine-versions-aurora."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "describe-engine-versions-aurora"
GROUP = 'engine_versions'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBEngineVersions for aurora-mysql returns Aurora-shaped catalog entries."""
    rds = ctx.client("rds")
    resp = rds.describe_db_engine_versions(Engine="aurora-mysql", MaxRecords=20)
    versions = resp["DBEngineVersions"]
    assert len(versions) > 0, "No Aurora MySQL engine versions returned"
    assert len(versions) <= 20, f"MaxRecords=20 not honored, got {len(versions)} entries"
    for v in versions:
        assert v.get("Engine") == "aurora-mysql", (
            f"Expected Engine=aurora-mysql, got {v.get('Engine')!r}"
        )
        assert v.get("EngineVersion"), f"Entry missing EngineVersion: {v!r}"
        assert v.get("DBParameterGroupFamily"), (
            f"Entry {v.get('EngineVersion')!r} missing DBParameterGroupFamily"
        )
        # SupportedEngineModes is populated only for Aurora engines, never for plain mysql/postgres
        # RDS entries.
        assert v.get("SupportedEngineModes"), (
            f"Aurora entry {v.get('EngineVersion')!r} missing SupportedEngineModes"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
