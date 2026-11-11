"""list-component-versions-pagination."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-component-versions-pagination"
GROUP = "data-plane"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListComponentVersions with a small maxResults paginates via nextToken and the union of pages
    contains exactly the versions created, with no duplicates or omissions."""
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-gg-pages-")
    versions = ["1.0.0", "2.0.0", "3.0.0"]
    base_arn = None
    for v in versions:
        resp = gg.create_component_version(inlineRecipe=_recipe_bytes(name, v))
        ctx.on_cleanup(lambda arn=resp["arn"]: _safe_delete_component(ctx, arn))
        base_arn = resp["arn"].rsplit(":versions:", 1)[0]

    seen: list[str] = []
    token = None
    pages = 0
    while True:
        kwargs = {"arn": base_arn, "maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        page = gg.list_component_versions(**kwargs)
        pages += 1
        seen.extend(v["componentVersion"] for v in page["componentVersions"])
        token = page.get("nextToken")
        if not token or pages > 10:
            break

    assert pages >= len(versions), f"expected at least {len(versions)} pages of size 1, got {pages}"
    assert sorted(seen) == sorted(versions), f"expected {versions}, saw {seen}"
    assert len(seen) == len(set(seen)), f"duplicate versions across pages: {seen}"
    # Greatest version first, consistent across page boundaries (not just within one page).
    assert seen == list(reversed(versions)), (
        f"expected pages to walk versions greatest-first {list(reversed(versions))}, saw {seen}"
    )


def _recipe_bytes(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-test",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    return json.dumps(recipe).encode("utf-8")


def _safe_delete_component(ctx, arn: str) -> None:
    gg = ctx.client("greengrassv2")
    try:
        gg.delete_component(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
