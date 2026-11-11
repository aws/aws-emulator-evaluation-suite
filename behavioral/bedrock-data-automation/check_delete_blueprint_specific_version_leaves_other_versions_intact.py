"""delete-blueprint-specific-version-leaves-other-versions-intact."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-blueprint-specific-version-leaves-other-versions-intact"
GROUP = "lifecycle"
SERVICES = ["bedrock-data-automation"]

_SCHEMA = json.dumps(
    {
        "class": "Versioned",
        "description": "version-delete schema",
        "properties": {"x": {"type": "string", "inferenceType": "explicit", "instruction": "x"}},
    }
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteBlueprint with a specific blueprintVersion removes only that version; a sibling
    version of the same Blueprint remains fully readable, the base LIVE stage keeps its own
    schema untouched, and a repeat delete of the now-dead version is itself well-defined."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-bp-verdel")
    # CreateBlueprintVersion snapshots the LIVE stage, so create without an explicit stage
    # (defaults to LIVE) rather than DEVELOPMENT.
    arn = bda.create_blueprint(blueprintName=name, type="DOCUMENT", schema=_SCHEMA)["blueprint"]["blueprintArn"]

    v1 = bda.create_blueprint_version(blueprintArn=arn)["blueprint"]["blueprintVersion"]
    v2 = bda.create_blueprint_version(blueprintArn=arn)["blueprint"]["blueprintVersion"]
    assert v1 != v2, f"two CreateBlueprintVersion calls on the same blueprint both returned {v1!r}"
    # Every version must go before the base blueprint can be deleted.
    def _cleanup():
        for version in (v1, v2):
            _delete_blueprint_if_present(bda, arn, version)
        _delete_blueprint_if_present(bda, arn)

    ctx.on_cleanup(_cleanup)

    bda.delete_blueprint(blueprintArn=arn, blueprintVersion=v1)

    code, message = _client_error(lambda: bda.get_blueprint(blueprintArn=arn, blueprintVersion=v1))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted version {v1}, got {code!r} ({message})"
    )
    assert message == "Incorrect Blueprint Arn or Version provided in the request.", (
        f"unexpected message: {message!r}"
    )

    # A repeat delete against the now-dead version is a mutation on a dead id: it must never
    # resurrect the version or silently succeed against something that no longer exists.
    second_delete_code, second_delete_message = _client_error(
        lambda: bda.delete_blueprint(blueprintArn=arn, blueprintVersion=v1)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected a repeat DeleteBlueprint on the already-deleted version {v1} to fail with "
        f"ResourceNotFoundException, got {second_delete_code!r}"
    )
    assert second_delete_message == "Incorrect Blueprint Arn or Version provided in the request.", (
        f"unexpected message: {second_delete_message!r}"
    )

    # The sibling version, never targeted, is still fully readable.
    still_there = bda.get_blueprint(blueprintArn=arn, blueprintVersion=v2)["blueprint"]
    assert still_there["blueprintVersion"] == v2, f"expected sibling version {v2}, got {still_there['blueprintVersion']!r}"
    assert still_there["schema"] == _SCHEMA, "sibling version's schema must be untouched by the version delete"

    # The base LIVE stage (not a specific version) is unaffected by the version delete: same
    # ARN, and — more to the point — the same schema it was created with.
    live = bda.get_blueprint(blueprintArn=arn, blueprintStage="LIVE")["blueprint"]
    assert live["blueprintArn"] == arn, f"expected LIVE stage to resolve to {arn}, got {live['blueprintArn']!r}"
    assert live["schema"] == _SCHEMA, "LIVE stage schema must be untouched by the specific-version delete"


def _client_error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_blueprint_if_present(bda, arn, version=None):
    from botocore.exceptions import ClientError

    kwargs = {"blueprintArn": arn} if version is None else {"blueprintArn": arn, "blueprintVersion": version}
    try:
        bda.delete_blueprint(**kwargs)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
