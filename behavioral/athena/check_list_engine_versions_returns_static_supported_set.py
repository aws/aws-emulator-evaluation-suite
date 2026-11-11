"""list-engine-versions-returns-static-supported-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-engine-versions-returns-static-supported-set"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEngineVersions returns the AWS-managed, account-independent set of supported
    Athena engine versions, including AUTO, and is stable across repeated calls."""
    athena = ctx.client("athena")

    versions_1 = _collect_engine_versions(athena)
    names_1 = {v["SelectedEngineVersion"] for v in versions_1 if "SelectedEngineVersion" in v}
    assert len(names_1) >= 2, f"expected at least 2 supported engine versions, got {names_1}"
    assert "AUTO" in names_1, f"expected 'AUTO' among supported engine versions, got {names_1}"
    assert any(name.startswith("Athena engine version") for name in names_1), (
        f"expected at least one named 'Athena engine version N' entry, got {names_1}"
    )

    # Server-managed and account-independent: identical on a second call.
    versions_2 = _collect_engine_versions(athena)
    names_2 = {v["SelectedEngineVersion"] for v in versions_2 if "SelectedEngineVersion" in v}
    assert names_2 == names_1, f"expected identical engine versions across calls, got {names_1} then {names_2}"


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
