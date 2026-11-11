"""resolve-component-candidates-match-and-missing."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolve-component-candidates-match-and-missing"
GROUP = "data-plane"
SERVICES = ["greengrassv2"]
AUTH_MESSAGE = "Unable to determine service/operation name to be authorized"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResolveComponentCandidates with IAM SigV4 credentials raises AccessDeniedException with the
    same exact message for a candidate naming a real component version and for one naming a
    component that was never created.
    """
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-gg-resolve-")
    version = "1.0.0"
    created = gg.create_component_version(inlineRecipe=_recipe_bytes(name, version))
    ctx.on_cleanup(lambda: _safe_delete_component(ctx, created["arn"]))

    code_real, message_real = _client_error(
        lambda: gg.resolve_component_candidates(
            platform={"name": "linux", "attributes": {"os": "linux", "architecture": "amd64"}},
            componentCandidates=[
                {"componentName": name, "componentVersion": version, "versionRequirements": {}}
            ],
        )
    )
    assert code_real == "AccessDeniedException", f"expected AccessDeniedException, got {code_real!r}"
    assert message_real == AUTH_MESSAGE, f"expected message {AUTH_MESSAGE!r}, got {message_real!r}"

    missing_name = ctx.unique_name("sim2real-gg-nosuchcomp-")
    code_missing, message_missing = _client_error(
        lambda: gg.resolve_component_candidates(
            platform={"name": "linux", "attributes": {"os": "linux", "architecture": "amd64"}},
            componentCandidates=[
                {"componentName": missing_name, "componentVersion": "1.0.0", "versionRequirements": {}}
            ],
        )
    )
    assert code_missing == "AccessDeniedException", f"expected AccessDeniedException, got {code_missing!r}"
    assert message_missing == AUTH_MESSAGE, f"expected message {AUTH_MESSAGE!r}, got {message_missing!r}"


def _recipe_bytes(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-test",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [
            {"Platform": {"os": "linux", "architecture": "amd64"}, "Lifecycle": {}}
        ],
    }
    return json.dumps(recipe).encode("utf-8")


def _safe_delete_component(ctx, arn: str) -> None:
    gg = ctx.client("greengrassv2")
    try:
        gg.delete_component(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects resolve_component_candidates with plain IAM credentials, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

