"""create-component-version-invalid-recipe-validation-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-component-version-invalid-recipe-validation-rejected"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateComponentVersion with a recipe missing ComponentName/ComponentVersion raises
    AccessDeniedException with the exact message and adds no component, while a well-formed
    recipe is created.
    """
    gg = ctx.client("greengrassv2")

    control_name = ctx.unique_name("sim2real-ggv2-badrecipe-control-")
    control_resp = gg.create_component_version(inlineRecipe=_make_recipe(control_name, "1.0.0"))
    ctx.on_cleanup(lambda: _delete_ignore_missing(gg, control_resp["arn"]))
    assert control_resp["componentName"] == control_name, (
        f"positive control did not register {control_name!r}: {control_resp!r}"
    )

    before = {c["arn"] for c in gg.list_components(scope="PRIVATE")["components"]}

    bad_recipe = json.dumps({"NotARecipe": True, "ComponentDescription": "missing required fields"}).encode(
        "utf-8"
    )
    code, msg = _error_code_and_message(lambda: gg.create_component_version(inlineRecipe=bad_recipe))
    assert code == "AccessDeniedException", f"got code={code!r} msg={msg!r}"
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        "Invalid Input: The component recipe doesn't specify a component name or version. Add "
        "ComponentName and ComponentVersion parameters to the recipe and try again. "
        f"User: {caller_arn} is not authorized to perform: null"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    after = {c["arn"] for c in gg.list_components(scope="PRIVATE")["components"]}
    assert after == before, (
        f"the rejected create registered a component: before={len(before)} entries, "
        f"after={len(after)} entries"
    )


def _make_recipe(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "invalid-recipe-validation positive control",
        "ComponentPublisher": "sim2real",
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    return json.dumps(recipe).encode("utf-8")


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected CreateComponentVersion to reject the malformed recipe, but it succeeded: {result!r}"
    )


def _delete_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
