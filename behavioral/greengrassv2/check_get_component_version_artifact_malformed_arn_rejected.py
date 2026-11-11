"""get-component-version-artifact-malformed-arn-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-component-version-artifact-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetComponentVersionArtifact raises ValidationException with its exact message both for a
    malformed arn and for a well-formed arn of a never-created component; a created version is
    describable.
    """
    gg = ctx.client("greengrassv2")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-gg-artifactmalformed-")
    created = gg.create_component_version(
        inlineRecipe=_recipe_bytes(name, "1.0.0"), tags={"env": "sim2real-behavioral"}
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: _safe_delete_component(ctx, arn))

    code, message = _error_code(
        lambda: gg.get_component_version_artifact(arn="not-an-arn", artifactName="thing.zip")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Invalid Input: Component version ARN not-an-arn is invalid"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Same operation, a different kind of bad arn: syntactically well-formed but naming a
    # component that was never created. Real AWS returns the identical ValidationException
    # here too rather than ResourceNotFoundException — so
    # this operation does not use ResourceNotFoundException to distinguish "malformed" from
    # "not found"; both collapse into ValidationException.
    account_id = sts.get_caller_identity()["Account"]
    missing_name = ctx.unique_name("sim2real-gg-missing-")
    nonexistent_arn = (
        f"arn:aws:greengrass:{ctx.region}:{account_id}:components:{missing_name}:versions:1.0.0"
    )
    control_code, control_message = _error_code(
        lambda: gg.get_component_version_artifact(arn=nonexistent_arn, artifactName="thing.zip")
    )
    assert control_code == "ValidationException", (
        f"expected ValidationException for a well-formed but nonexistent arn, got {control_code!r}"
    )
    expected_missing = (
        f"Component ({missing_name}:1.0.0) or Artifact (thing.zip) for account {account_id} does not exist"
    )
    assert control_message == expected_missing, (
        f"expected message {expected_missing!r}, got {control_message!r}"
    )

    # Independent read at a different operation: the arn under test really does belong to a real,
    # describable component version.
    described = gg.describe_component(arn=arn)
    assert described["componentName"] == name, f"expected {name!r}, got {described.get('componentName')!r}"


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


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
