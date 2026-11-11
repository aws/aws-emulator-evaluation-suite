"""list-release-labels-then-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-release-labels-then-describe"
GROUP = 'release-labels'
SERVICES = ['emr']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A release label surfaced by ListReleaseLabels is describable via DescribeReleaseLabel."""
    emr = ctx.client("emr")
    labels = emr.list_release_labels().get("ReleaseLabels", [])
    assert labels, "ListReleaseLabels returned no release labels"

    label = labels[0]
    desc = emr.describe_release_label(ReleaseLabel=label)
    assert desc.get("ReleaseLabel") == label, (
        f"describe_release_label({label!r}) returned ReleaseLabel={desc.get('ReleaseLabel')!r}"
    )
    apps = desc.get("Applications")
    assert apps, f"release label {label!r} surfaced by ListReleaseLabels reports no Applications: {desc}"
    for app in apps:
        assert app.get("Name") and app.get("Version"), (
            f"release {label!r} application entry missing Name/Version: {app}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
