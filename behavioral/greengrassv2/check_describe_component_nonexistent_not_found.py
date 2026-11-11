"""describe-component-nonexistent-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-component-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeComponent on a never-created component version ARN raises ResourceNotFoundException
    with the exact message, while on a created component it returns its componentName.
    """
    gg = ctx.client("greengrassv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-ggv2-missing-")
    version = "1.0.0"
    real_arn = _create_component(ctx, gg, name, version)

    described = gg.describe_component(arn=real_arn)
    assert described["componentName"] == name, (
        f"positive control failed: expected componentName {name!r}, got "
        f"{described.get('componentName')!r}"
    )

    # Perturb only the component name of a REAL arn (same account/region/partition), so a
    # not-found is never confused with a fabricated ARN landing outside this identity's
    # resource scope.
    bogus_arn = f"arn:aws:greengrass:{ctx.region}:{account_id}:components:{name}-absent:versions:{version}"
    code, message = _client_error(lambda: gg.describe_component(arn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created component version, got {code!r}"
    )
    expected = f"Component ({name}-absent:{version}) does not exist in account {account_id}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_component(ctx, gg, name: str, version: str) -> str:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentPublisher": "sim2real",
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    resp = gg.create_component_version(
        inlineRecipe=json.dumps(recipe).encode("utf-8"),
        tags={"sim2real-check": CHECK},
    )
    arn = resp["arn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(gg, arn))
    return arn


def _delete_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
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
