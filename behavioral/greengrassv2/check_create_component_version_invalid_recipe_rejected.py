"""create-component-version-invalid-recipe-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-component-version-invalid-recipe-rejected"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateComponentVersion with an inlineRecipe that is neither JSON nor YAML raises
    AccessDeniedException with the exact message naming the caller and lists no such component,
    while a well-formed recipe is created.
    """
    ggv2 = ctx.client("greengrassv2")
    good_name = ctx.unique_name("sim2real-ggv2-goodrecipe-")

    good_recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": good_name,
        "ComponentVersion": "1.0.0",
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    arn = ggv2.create_component_version(inlineRecipe=json.dumps(good_recipe).encode("utf-8"))["arn"]
    ctx.on_cleanup(lambda: ggv2.delete_component(arn=arn))

    bad_name = ctx.unique_name("sim2real-ggv2-badrecipe-")
    garbage = (
        "]] this is neither JSON nor YAML {{ :: -- \x00\x01 "
        + bad_name
    ).encode("utf-8")
    code, msg = _error_code_and_message(lambda: ggv2.create_component_version(inlineRecipe=garbage))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got code={code!r} msg={msg!r}"
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        f"Invalid recipe format; line: 1, column: 1. User: {caller_arn} is not authorized to perform: null"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    private_components = ggv2.list_components(scope="PRIVATE")["components"]
    assert not any(c["componentName"] == bad_name for c in private_components), private_components


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected create_component_version to reject an unparseable recipe, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
