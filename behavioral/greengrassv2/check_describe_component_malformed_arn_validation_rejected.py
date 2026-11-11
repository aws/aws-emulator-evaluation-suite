"""describe-component-malformed-arn-validation-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-component-malformed-arn-validation-rejected"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeComponent rejects a syntactically malformed component-version ARN with
    ValidationException rather than silently returning nothing or a server error; a
    real component-version ARN still describes correctly on the same operation."""
    gg = ctx.client("greengrassv2")

    code, message = _client_error(lambda: gg.describe_component(arn="not-a-valid-arn"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Invalid Input: Component version ARN not-a-valid-arn is invalid"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: DescribeComponent on a real component-version arn still works,
    # so the rejection above is specific to the malformed arn, not every call.
    name = ctx.unique_name("sim2real-ggv2-comp-")
    version = "1.0.0"
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    arn = gg.create_component_version(
        inlineRecipe=json.dumps(recipe).encode("utf-8"),
        tags={"env": "sim2real", "purpose": "behavioral-check"},
    )["arn"]
    ctx.on_cleanup(lambda: _delete_component_ignore_missing(gg, arn))

    described = gg.describe_component(arn=arn)
    assert described["componentName"] == name, (
        f"expected componentName {name!r}, got {described.get('componentName')!r}"
    )
    assert described["componentVersion"] == version, (
        f"expected componentVersion {version!r}, got {described.get('componentVersion')!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_component_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
