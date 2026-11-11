"""list-component-versions-pagination-next-token."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-component-versions-pagination-next-token"
GROUP = "data-plane"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListComponentVersions with maxResults=1 pages through every version via nextToken
    without skipping or duplicating any of them."""
    ggv2 = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-ggv2-comp-")
    all_versions = ["1.0.0", "1.0.1", "1.0.2"]
    arns = {}
    for version in all_versions:
        arn = ggv2.create_component_version(
            inlineRecipe=json.dumps(_recipe(name, version)).encode("utf-8"),
            tags={"sim2real-key": "sim2real-value"},
        )["arn"]
        arns[version] = arn
        ctx.on_cleanup(lambda a=arn: ggv2.delete_component(arn=a))

    any_arn = next(iter(arns.values()))
    seen_versions: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"arn": any_arn, "maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = ggv2.list_component_versions(**kwargs)
        page = resp["componentVersions"]
        assert len(page) <= 1, f"maxResults=1 but got {len(page)} results in one page"
        seen_versions.extend(v["componentVersion"] for v in page)
        next_token = resp.get("nextToken")
        pages += 1
        if not next_token or pages > 10:
            break

    assert sorted(seen_versions) == sorted(all_versions), seen_versions
    assert len(seen_versions) == len(set(seen_versions)), f"duplicate entries across pages: {seen_versions}"
    assert pages >= len(all_versions), f"expected at least {len(all_versions)} pages, got {pages}"


def _recipe(name: str, version: str) -> dict:
    return {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
