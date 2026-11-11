"""describe-release-label-lists-applications."""
from __future__ import annotations

from behavioral_harness import tags

RELEASE_LABEL = "emr-6.15.0"

CHECK = "describe-release-label-lists-applications"
GROUP = 'release-labels'
SERVICES = ['emr']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeReleaseLabel returns the application inventory for a known release."""
    emr = ctx.client("emr")
    desc = emr.describe_release_label(ReleaseLabel=RELEASE_LABEL)
    assert desc["ReleaseLabel"] == RELEASE_LABEL, (
        f"expected ReleaseLabel {RELEASE_LABEL!r}, got {desc.get('ReleaseLabel')!r}"
    )
    apps_by_name = {a["Name"].lower(): a for a in desc.get("Applications", [])}
    assert len(apps_by_name) >= 15, (
        f"emr-6.15.0 must ship its full application catalog (>=15 apps), "
        f"got {len(apps_by_name)}: {sorted(apps_by_name)}"
    )
    assert "hadoop" in apps_by_name, f"emr-6 release must ship Hadoop, got {sorted(apps_by_name)[:10]}"
    assert "spark" in apps_by_name, f"emr-6 release must ship Spark, got {sorted(apps_by_name)[:10]}"
    assert apps_by_name["hadoop"].get("Version") == "3.3.6", (
        f"emr-6.15.0 must pin Hadoop at 3.3.6, got {apps_by_name['hadoop'].get('Version')!r}"
    )
    assert apps_by_name["spark"].get("Version") == "3.4.1", (
        f"emr-6.15.0 must pin Spark at 3.4.1, got {apps_by_name['spark'].get('Version')!r}"
    )
    for app in desc["Applications"]:
        assert app.get("Version"), f"application {app['Name']} must report a Version"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
