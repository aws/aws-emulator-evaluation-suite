"""list-release-labels-prefix-filter-and-ordering."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-release-labels-prefix-filter-and-ordering"
GROUP = 'release-labels'
SERVICES = ['emr']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListReleaseLabels honours the Prefix filter and returns newest-first ordering."""
    emr = ctx.client("emr")
    labels = emr.list_release_labels(Filters={"Prefix": "emr-6"})["ReleaseLabels"]
    assert labels, "Prefix filter emr-6 returned no release labels"
    assert all(x.startswith("emr-6") for x in labels), (
        f"Prefix filter leaked non-matching labels: {[x for x in labels if not x.startswith('emr-6')][:5]}"
    )

    def version_key(label):
        return [int(part) for part in label.removeprefix("emr-").split(".") if part.isdigit()]

    keys = [version_key(x) for x in labels]
    assert keys == sorted(keys, reverse=True), (
        f"release labels must be strictly newest-first (monotonically decreasing), got {labels}"
    )

    # A prefix that cannot match anything yields an empty list, not an error.
    empty = emr.list_release_labels(Filters={"Prefix": "emr-0"})["ReleaseLabels"]
    assert empty == [], f"non-matching prefix must return an empty list, got {empty[:5]}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
