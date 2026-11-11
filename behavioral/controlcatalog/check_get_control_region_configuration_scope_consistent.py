"""get-control-region-configuration-scope-consistent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-control-region-configuration-scope-consistent"
GROUP = "semantics"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetControl reports RegionConfiguration.Scope GLOBAL or REGIONAL, and a REGIONAL control lists a
    non-empty DeployableRegions of region codes, so a caller knows where it can be enabled."""

    cc = ctx.client("controlcatalog")
    page = cc.list_controls(MaxResults=25)
    controls = page["Controls"]
    assert len(controls) > 0, "list_controls returned no controls at all"

    found_regional = False
    for c in controls:
        got = cc.get_control(ControlArn=c["Arn"])
        rc = got["RegionConfiguration"]
        assert rc["Scope"] in ("GLOBAL", "REGIONAL"), f"unexpected Scope {rc['Scope']!r} on {c['Arn']}"
        if rc["Scope"] == "REGIONAL":
            found_regional = True
            deployable = rc.get("DeployableRegions") or []
            assert len(deployable) > 0, f"REGIONAL control {c['Arn']} reported no DeployableRegions"
            assert all(isinstance(r, str) and r for r in deployable), (
                f"REGIONAL control {c['Arn']} has a non-string or empty entry in DeployableRegions: {deployable!r}"
            )

    if not found_regional:
        raise AssertionError(
            "no REGIONAL-scoped control found among the first 25 controls scanned; "
            "closeable by scanning more of the catalog"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
