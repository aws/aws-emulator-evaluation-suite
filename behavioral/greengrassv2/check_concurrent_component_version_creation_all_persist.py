"""concurrent-component-version-creation-all-persist."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-component-version-creation-all-persist"
GROUP = "concurrency"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrently creating N distinct versions of the same component name all persist: the
    registry's version list ends up with exactly N entries, one per racer, with none lost or
    corrupted by the concurrent writes."""
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-gg-race-")
    n = 6
    versions = [f"1.0.{i}" for i in range(n)]
    component_tags = {"sim2real-check": "concurrent-component-version-creation-all-persist"}

    def create(version: str):
        return gg.create_component_version(
            inlineRecipe=_recipe_bytes(name, version), tags=component_tags
        )

    results = []
    errors = []
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = {pool.submit(create, v): v for v in versions}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except ClientError as exc:
                errors.append((futures[future], exc.response["Error"]["Code"]))

    for arn in (r["arn"] for r in results):
        ctx.on_cleanup(lambda arn=arn: _safe_delete_component(ctx, arn))

    assert not errors, f"unexpected racer failures: {errors}"
    assert len(results) == n, f"expected {n} successful creates, got {len(results)}"

    base_arn = results[0]["arn"].rsplit(":versions:", 1)[0]
    registered = {v["componentVersion"] for v in _list_all_versions(gg, base_arn)}
    assert registered == set(versions), (
        f"expected registry to hold {sorted(versions)}, found {sorted(registered)}"
    )


def _list_all_versions(gg, base_arn: str):
    items = []
    token = None
    for _ in range(20):
        kwargs = {"arn": base_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = gg.list_component_versions(**kwargs)
        items.extend(page["componentVersions"])
        token = page.get("nextToken")
        if not token:
            break
    return items


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
