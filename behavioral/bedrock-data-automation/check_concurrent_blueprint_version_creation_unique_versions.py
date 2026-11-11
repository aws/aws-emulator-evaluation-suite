"""concurrent-blueprint-version-creation-unique-versions."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-blueprint-version-creation-unique-versions"
GROUP = "concurrency"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateBlueprintVersion calls against the same Blueprint each get a distinct,
    monotonically-assigned version number -- the version counter is not lost under contention."""
    bda = ctx.client("bedrock-data-automation")
    arn = bda.create_blueprint(
        blueprintName=ctx.unique_name("sim2real-bp-concurrent-"),
        type="DOCUMENT",
        schema=_blueprint_schema(),
        tags=[{"key": "purpose", "value": "sim2real-concurrent-version"}],
    )["blueprint"]["blueprintArn"]

    def _delete_blueprint_and_versions(versions_to_delete):
        from botocore.exceptions import ClientError

        # Real AWS refuses DeleteBlueprint(no version) while any version still exists
        # (ValidationException: "must delete all versions of the blueprint before you can
        # delete the blueprint"), so every version this check created must be deleted first.
        for v in versions_to_delete:
            try:
                bda.delete_blueprint(blueprintArn=arn, blueprintVersion=str(v))
            except ClientError as err:
                if err.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        try:
            bda.delete_blueprint(blueprintArn=arn)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    created_versions: list[str] = []
    ctx.on_cleanup(lambda: _delete_blueprint_and_versions(created_versions))

    racer_count = 5

    def _create_version():
        return bda.create_blueprint_version(blueprintArn=arn)["blueprint"]["blueprintVersion"]

    versions = []
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_create_version) for _ in range(racer_count)]
        for f in as_completed(futures):
            versions.append(f.result())

    created_versions.extend(versions)

    assert len(versions) == racer_count, f"expected {racer_count} results, got {len(versions)}: {versions}"
    assert len(set(versions)) == racer_count, f"version numbers collided under contention: {versions}"

    # The version numbers assigned are exactly N contiguous integers -- no gaps, no reuse.
    nums = sorted(int(v) for v in versions)
    assert nums == list(range(nums[0], nums[0] + racer_count)), f"non-contiguous versions: {nums}"

    # The terminal read is independent of the mutating CreateBlueprintVersion calls: each version
    # must be separately retrievable via GetBlueprint(blueprintVersion=...) at the destination, not
    # just echoed back by the call that created it.
    for v in versions:
        fetched = bda.get_blueprint(blueprintArn=arn, blueprintVersion=str(v))["blueprint"]
        assert str(fetched["blueprintVersion"]) == str(v), (
            f"GetBlueprint(blueprintVersion={v}) returned version {fetched['blueprintVersion']!r}"
        )

    # The delete is a free negative: an operation that just worked (GetBlueprint) must now fail with
    # the specific not-found code once the blueprint this check created (all versions and all) is
    # torn down.
    _delete_blueprint_and_versions(versions)
    from botocore.exceptions import ClientError

    try:
        bda.get_blueprint(blueprintArn=arn)
        raise AssertionError(f"expected ResourceNotFoundException after delete, got success for {arn}")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        assert message == "Blueprint Arn not found.", f"unexpected message: {message!r}"


def _blueprint_schema(class_name: str = "SimparityTestDoc", field: str = "test_field") -> str:
    return json.dumps(
        {
            "class": class_name,
            "description": "Simparity behavioral fidelity test blueprint",
            "properties": {
                field: {
                    "type": "string",
                    "inferenceType": "explicit",
                    "instruction": "Extract the test field value",
                }
            },
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
