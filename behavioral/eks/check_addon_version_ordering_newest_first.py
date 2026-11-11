"""addon-version-ordering-newest-first."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "addon-version-ordering-newest-first"
GROUP = 'ordering'
SERVICES = ['eks']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """[ordering] DescribeAddonVersions returns each AWS-owned add-on's versions in strictly descending version order (newest first)."""
    c = ctx.client("eks")

    def parse(version: str) -> tuple:
        # "v1.19.6-eksbuild.7" -> (1, 19, 6, 7)
        core, _, build = version.lstrip("v").partition("-eksbuild.")
        parts = [int(p) for p in core.split(".") if p.isdigit()]
        parts.append(int(build) if build.isdigit() else 0)
        return tuple(parts)

    checked = 0
    for addon_name in ("vpc-cni", "coredns", "kube-proxy"):
        resp = c.describe_addon_versions(addonName=addon_name)
        addons = resp.get("addons", [])
        assert addons, f"no catalogue entry for {addon_name}"
        for addon in addons:
            assert addon["owner"] == "aws", addon
            keys = [parse(v["addonVersion"]) for v in addon["addonVersions"]]
            assert len(keys) > 1, f"{addon_name} has too few versions to order"
            for older, newer in zip(keys[1:], keys[:-1]):
                assert newer > older, (
                    f"{addon_name} versions not newest-first: {newer} follows {older}"
                )
            checked += 1
    assert checked >= 3, checked


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
