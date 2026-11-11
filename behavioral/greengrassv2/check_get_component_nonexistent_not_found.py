"""get-component-nonexistent-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-component-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetComponent on a never-created component version ARN raises ResourceNotFoundException with
    the exact message, while on a real version it returns the recipe with its ComponentName.
    """
    gg = ctx.client("greengrassv2")
    account = ctx.client("sts").get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-gg-norecipe-")
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": "1.0.0",
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    real_arn = gg.create_component_version(
        inlineRecipe=json.dumps(recipe).encode("utf-8"),
        tags={"sim2real-check": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: gg.delete_component(arn=real_arn))

    # Positive control: GetComponent on a real component version succeeds and returns its recipe.
    real_recipe = json.loads(gg.get_component(arn=real_arn)["recipe"])
    assert real_recipe["ComponentName"] == name, (
        f"expected recipe for {name!r}, got {real_recipe.get('ComponentName')!r}"
    )

    missing_name = ctx.unique_name("sim2real-gg-norecipe-missing-")
    bogus_arn = f"arn:aws:greengrass:{ctx.region}:{account}:components:{missing_name}:versions:1.0.0"
    code, message = _client_error(lambda: gg.get_component(arn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"PRIVATE component ({missing_name}:1.0.0) under account {account} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
