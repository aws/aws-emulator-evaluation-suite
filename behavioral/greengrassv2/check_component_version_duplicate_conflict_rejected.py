"""component-version-duplicate-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "component-version-duplicate-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-creating an existing componentName+componentVersion with different recipe content
    is rejected with ConflictException, the original recipe is untouched, and creating a
    genuinely new version for the same component still succeeds (positive control)."""
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-ggv2-dup-")
    version = "1.0.0"

    resp1 = gg.create_component_version(inlineRecipe=_make_recipe(name, version, "original-A"))
    arn1 = resp1["arn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(gg, arn1))
    state = _poll_component_state(gg, arn1)
    assert state == "DEPLOYABLE", f"expected the original version to become DEPLOYABLE, got {state!r}"

    code, message = _error_code(
        lambda: gg.create_component_version(inlineRecipe=_make_recipe(name, version, "conflicting-B"))
    )
    assert code == "ConflictException", (
        f"expected ConflictException re-creating {name}@{version} with different content, got {code!r}"
    )
    expected = (
        f"Component [{name} : {version}] for account [{ctx.account}] already exists with state: [DEPLOYABLE]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    got = gg.get_component(arn=arn1, recipeOutputFormat="JSON")
    recipe = json.loads(got["recipe"])
    assert recipe["ComponentDescription"] == "original-A", (
        f"expected the original recipe untouched by the rejected write, got description {recipe['ComponentDescription']!r}"
    )

    version2 = "1.0.1"
    resp2 = gg.create_component_version(inlineRecipe=_make_recipe(name, version2, "original-A-v2"))
    arn2 = resp2["arn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(gg, arn2))
    assert resp2["componentVersion"] == version2, (
        f"expected create_component_version to report componentVersion {version2!r}, got {resp2['componentVersion']!r}"
    )

    got2 = gg.get_component(arn=arn2, recipeOutputFormat="JSON")
    recipe2 = json.loads(got2["recipe"])
    assert recipe2["ComponentDescription"] == "original-A-v2", (
        f"expected an independent read of {name}@{version2} to show original-A-v2, got {recipe2['ComponentDescription']!r}"
    )


def _make_recipe(name: str, version: str, description: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": description,
        "ComponentPublisher": "sim2real",
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    return json.dumps(recipe).encode("utf-8")


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_component_state(gg, arn: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = gg.describe_component(arn=arn)["status"]["componentState"]
        if state in ("DEPLOYABLE", "FAILED"):
            return state
        time.sleep(interval_s)
    raise AssertionError(f"component {arn} did not reach a terminal state within {timeout_s}s, last={state!r}")


def _delete_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
