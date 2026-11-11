"""list-components-scope-private-isolated."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-components-scope-private-isolated"
GROUP = "data-plane"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created private component appears when ListComponents is scoped to PRIVATE, but not
    when scoped to PUBLIC (the AWS-provided component catalog)."""
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-gg-scope-")
    created = gg.create_component_version(
        inlineRecipe=_recipe_bytes(name, "1.0.0"), tags={"env": "sim2real-behavioral"}
    )
    ctx.on_cleanup(lambda: _safe_delete_component(ctx, created["arn"]))

    private_listing = _list_all(gg, "PRIVATE")
    private_names = {c["componentName"] for c in private_listing}
    assert name in private_names, f"{name!r} missing from PRIVATE scope listing"

    public_listing = _list_all(gg, "PUBLIC")
    public_names = {c["componentName"] for c in public_listing}
    public_arns = {c["arn"] for c in public_listing}
    assert name not in public_names, f"private component {name!r} leaked into PUBLIC scope listing"
    assert created["arn"] not in public_arns, (
        f"private component arn {created['arn']!r} leaked into PUBLIC scope listing"
    )


def _list_all(gg, scope: str):
    items = []
    token = None
    for _ in range(20):
        kwargs = {"scope": scope, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = gg.list_components(**kwargs)
        items.extend(page["components"])
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
