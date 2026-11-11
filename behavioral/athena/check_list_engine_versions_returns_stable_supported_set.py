"""list-engine-versions-returns-stable-supported-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-engine-versions-returns-stable-supported-set"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEngineVersions returns a non-empty set of supported engine versions that includes
    'Athena engine version 3' and is identical across repeated calls."""
    athena = ctx.client("athena")

    first = _collect_engine_versions(athena)
    assert len(first) > 0, "ListEngineVersions returned an empty EngineVersions list"

    # EngineVersions is a list of EngineVersion structures (SelectedEngineVersion /
    # EffectiveEngineVersion), not plain version-name strings.
    for entry in first:
        assert isinstance(entry, dict), f"expected an EngineVersion structure, got {entry!r}"
        version = entry.get("SelectedEngineVersion")
        assert isinstance(version, str) and len(version) > 0, (
            f"expected a non-empty SelectedEngineVersion string, got {version!r} in {entry!r}"
        )

    versions = {entry["SelectedEngineVersion"] for entry in first}
    assert "Athena engine version 3" in versions, versions

    second = _collect_engine_versions(athena)
    second_versions = {entry["SelectedEngineVersion"] for entry in second}
    assert second_versions == versions, "ListEngineVersions is not stable across calls"


def _collect_engine_versions(athena) -> list[dict]:
    out: list[dict] = []
    kwargs: dict = {}
    while True:
        resp = athena.list_engine_versions(**kwargs)
        out.extend(resp["EngineVersions"])
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
