"""delete-component-nonexistent-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-component-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteComponent on a never-created component version ARN raises ResourceNotFoundException
    with the exact message; deleting a real version succeeds and DescribeComponent then raises
    the same.
    """
    gg = ctx.client("greengrassv2")

    control_name = ctx.unique_name("sim2real-ggv2-comp-")
    real_arn = gg.create_component_version(
        inlineRecipe=_recipe_bytes(control_name, "1.0.0"),
        tags={"sim2real": "behavioral-check"},
    )["arn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: gg.delete_component(arn=real_arn)))

    # A well-formed sibling ARN, same account/region/ARN shape as the real one above, whose
    # component was never created.
    prefix = real_arn.rsplit(":components:", 1)[0]
    never_created_name = ctx.unique_name("sim2real-ggv2-missing-")
    bogus_arn = f"{prefix}:components:{never_created_name}:versions:1.0.0"

    account = real_arn.split(":")[4]
    code, message = _client_error(lambda: gg.delete_component(arn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Component [{never_created_name} : 1.0.0] in the accountId [{account}] does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: the identical operation against a real component version succeeds
    gg.delete_component(arn=real_arn)

    describe_code, describe_message = _client_error(lambda: gg.describe_component(arn=real_arn))
    assert describe_code == "ResourceNotFoundException", (
        f"real component still describable after delete: {describe_code!r}"
    )
    expected = f"Component ({control_name}:1.0.0) does not exist in account {account}."
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"


def _recipe_bytes(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    return json.dumps(recipe).encode("utf-8")


def _swallow_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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
