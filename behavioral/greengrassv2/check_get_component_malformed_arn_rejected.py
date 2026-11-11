"""get-component-malformed-arn-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-component-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetComponent rejects an arn that doesn't match the component-version ARN pattern; a real arn still works."""
    ggv2 = ctx.client("greengrassv2")

    code, message = _client_error(lambda: ggv2.get_component(arn="not-a-valid-arn"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Invalid Input: Component version ARN not-a-valid-arn is invalid"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a real component version's arn works.
    name = ctx.unique_name("sim2real-ggv2-comp-")
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": "1.0.0",
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    arn = ggv2.create_component_version(inlineRecipe=json.dumps(recipe).encode("utf-8"))["arn"]
    ctx.on_cleanup(lambda: ggv2.delete_component(arn=arn))
    ggv2.tag_resource(resourceArn=arn, tags={"sim2real": "get-component-malformed-arn-rejected"})

    resp = ggv2.get_component(arn=arn)
    fetched_name = json.loads(resp["recipe"])["ComponentName"]
    assert fetched_name == name, f"expected component name {name!r}, got {fetched_name!r}"


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
