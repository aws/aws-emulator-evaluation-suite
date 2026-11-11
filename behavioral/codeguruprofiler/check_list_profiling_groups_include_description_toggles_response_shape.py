"""list-profiling-groups-include-description-toggles-response-shape."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-profiling-groups-include-description-toggles-response-shape"
GROUP = "lifecycle"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListProfilingGroups switches its response shape based on includeDescription:
    with it False, only "profilingGroupNames" is populated (no "profilingGroups"); with it
    True, only "profilingGroups" (full descriptions) is populated (no "profilingGroupNames")."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    cgp.create_profiling_group(profilingGroupName=name, tags={"env": "sim2real"})

    names_only_found = False
    for page in _paginate(cgp, includeDescription=False):
        assert "profilingGroups" not in page, (
            f"includeDescription=False must omit profilingGroups, got keys {sorted(page)}"
        )
        if name in page.get("profilingGroupNames", []):
            names_only_found = True
    assert names_only_found, f"{name} missing from ListProfilingGroups profilingGroupNames"

    described_found = None
    for page in _paginate(cgp, includeDescription=True):
        assert "profilingGroupNames" not in page, (
            f"includeDescription=True must omit profilingGroupNames, got keys {sorted(page)}"
        )
        for pg in page.get("profilingGroups", []):
            if pg["name"] == name:
                described_found = pg
    assert described_found is not None, f"{name} missing from ListProfilingGroups profilingGroups"
    assert described_found["computePlatform"] == "Default", (
        f"expected computePlatform 'Default' for {name}, got {described_found['computePlatform']!r}"
    )


def _paginate(cgp, **kwargs):
    next_token = None
    for _ in range(25):
        call_kwargs = dict(kwargs, maxResults=1000)
        if next_token:
            call_kwargs["nextToken"] = next_token
        page = cgp.list_profiling_groups(**call_kwargs)
        yield page
        next_token = page.get("nextToken")
        if not next_token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
