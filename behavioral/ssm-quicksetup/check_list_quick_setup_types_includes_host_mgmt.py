"""list-quick-setup-types-includes-host-mgmt."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-quick-setup-types-includes-host-mgmt"
GROUP = "catalog"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListQuickSetupTypes returns the static catalog of configuration types, including the
    well-known AWSQuickSetupType-SSMHostMgmt type with a non-empty LatestVersion string."""
    qs = ctx.client("ssm-quicksetup")
    resp = qs.list_quick_setup_types()
    types = resp["QuickSetupTypeList"]
    assert len(types) > 0, f"ListQuickSetupTypes returned an empty catalog: {resp}"

    host_mgmt = next((t for t in types if t["Type"] == "AWSQuickSetupType-SSMHostMgmt"), None)
    assert host_mgmt is not None, "AWSQuickSetupType-SSMHostMgmt missing from ListQuickSetupTypes catalog"
    assert isinstance(host_mgmt["LatestVersion"], str) and len(host_mgmt["LatestVersion"]) > 0, (
        f"AWSQuickSetupType-SSMHostMgmt has no well-formed LatestVersion: {host_mgmt!r}"
    )

    # every entry in the catalog must carry a well-formed type string and version
    for t in types:
        assert t["Type"].startswith("AWSQuickSetupType-"), f"catalog entry has unexpected Type: {t!r}"
        assert isinstance(t["LatestVersion"], str) and len(t["LatestVersion"]) > 0, (
            f"catalog entry has no well-formed LatestVersion: {t!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
