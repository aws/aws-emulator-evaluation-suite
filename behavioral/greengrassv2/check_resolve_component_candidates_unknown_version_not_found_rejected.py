"""resolve-component-candidates-unknown-version-not-found-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolve-component-candidates-unknown-version-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResolveComponentCandidates with IAM SigV4 credentials raises AccessDeniedException with the
    exact message for a real and a never-created component version alike, before any existence
    check.
    """
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-gg-resolvever-")
    real_version = "1.0.0"
    created = gg.create_component_version(
        inlineRecipe=_recipe_bytes(name, real_version),
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_component(ctx, created["arn"]))
    platform = {"name": "linux", "attributes": {"os": "linux", "architecture": "amd64"}}

    expected = "Unable to determine service/operation name to be authorized"
    code_real, message_real = _error_code(
        lambda: gg.resolve_component_candidates(
            platform=platform,
            componentCandidates=[
                {"componentName": name, "componentVersion": real_version, "versionRequirements": {}}
            ],
        )
    )
    assert code_real == "AccessDeniedException", f"expected AccessDeniedException, got {code_real!r}"
    assert message_real == expected, f"expected message {expected!r}, got {message_real!r}"

    never_created_version = "9.9.9"
    code_missing, message_missing = _error_code(
        lambda: gg.resolve_component_candidates(
            platform=platform,
            componentCandidates=[
                {
                    "componentName": name,
                    "componentVersion": never_created_version,
                    "versionRequirements": {},
                }
            ],
        )
    )
    assert code_missing == "AccessDeniedException", f"expected AccessDeniedException, got {code_missing!r}"
    assert message_missing == expected, f"expected message {expected!r}, got {message_missing!r}"


def _recipe_bytes(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-test",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux", "architecture": "amd64"}, "Lifecycle": {}}],
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

