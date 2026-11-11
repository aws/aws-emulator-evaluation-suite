"""describe-addon-versions-filter-shape."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "describe-addon-versions-filter-shape"
GROUP = 'metadata'
SERVICES = ['eks']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAddonVersions honours the addonName filter and returns compatibility metadata with exactly one default version."""
    c = ctx.client("eks")
    resp = c.describe_addon_versions(addonName="vpc-cni")
    addons = resp.get("addons", [])
    assert addons, "expected at least one addon entry for vpc-cni"

    for addon in addons:
        assert addon["addonName"] == "vpc-cni", addon["addonName"]
        assert addon.get("type"), addon
        versions = addon.get("addonVersions", [])
        assert versions, addon

        defaults_by_cluster_version: dict = {}
        for info in versions:
            assert info["addonVersion"].startswith("v"), info["addonVersion"]
            compat = info.get("compatibilities", [])
            assert compat, info
            for entry in compat:
                cv = entry["clusterVersion"]
                assert cv.startswith("1."), entry
                if entry.get("defaultVersion"):
                    defaults_by_cluster_version.setdefault(cv, set()).add(info["addonVersion"])
        assert defaults_by_cluster_version, "no version flagged defaultVersion for any k8s version"
        for cv, flagged in defaults_by_cluster_version.items():
            # Exactly one, never zero (checked above) or more than one: CreateAddon without an
            # explicit addonVersion resolves to THE default, so two defaults for the same
            # clusterVersion would make that resolution non-deterministic.
            assert len(flagged) == 1, (
                f"vpc-cni advertises {len(flagged)} default versions for k8s {cv}: "
                f"{sorted(flagged)!r}; exactly one is required"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
