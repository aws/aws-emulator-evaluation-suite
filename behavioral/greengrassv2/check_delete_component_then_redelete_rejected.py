"""delete-component-then-redelete-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-component-then-redelete-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteComponent removes the version from the registry (DescribeComponent then 404s), and a
    second DeleteComponent on the same now-deleted ARN is rejected with ResourceNotFoundException
    rather than silently succeeding again."""
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-gg-del-")
    version = "1.0.0"
    created = gg.create_component_version(inlineRecipe=_recipe_bytes(name, version))
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(gg, arn))

    # positive control: the first delete of an existing component version succeeds
    gg.delete_component(arn=arn)

    account = arn.split(":")[4]
    describe_expected = f"Component ({name}:{version}) does not exist in account {account}."
    code_after_delete, message_after_delete = _expect_rejected(lambda: gg.describe_component(arn=arn))
    assert code_after_delete == "ResourceNotFoundException", (
        f"component still describable after delete: {code_after_delete!r}"
    )
    assert message_after_delete == describe_expected, (
        f"expected message {describe_expected!r}, got {message_after_delete!r}"
    )

    # negative: deleting the already-deleted ARN again is rejected, not a silent no-op success
    code_redelete, message_redelete = _expect_rejected(lambda: gg.delete_component(arn=arn))
    assert code_redelete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on redelete, got {code_redelete!r}"
    )
    redelete_expected = f"Component [{name} : {version}] in the accountId [{account}] does not exist"
    assert message_redelete == redelete_expected, (
        f"expected message {redelete_expected!r}, got {message_redelete!r}"
    )

    # the rejected redelete attempt must not have resurrected or otherwise mutated the record
    code_after_redelete, message_after_redelete = _expect_rejected(lambda: gg.describe_component(arn=arn))
    assert code_after_redelete == "ResourceNotFoundException", (
        f"component describable after a rejected redelete attempt: {code_after_redelete!r}"
    )
    assert message_after_redelete == describe_expected, (
        f"expected message {describe_expected!r}, got {message_after_redelete!r}"
    )


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


def _expect_rejected(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
