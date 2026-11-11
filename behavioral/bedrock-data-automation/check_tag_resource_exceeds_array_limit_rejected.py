"""tag-resource-exceeds-array-limit-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-array-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]

_SCHEMA = json.dumps(
    {
        "class": "Quota",
        "description": "quota schema",
        "properties": {"x": {"type": "string", "inferenceType": "explicit", "instruction": "x"}},
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with more than 200 tags, sent past client-side validation, is refused by the
    service with ValidationException and the exact length message and applies no tag, while tagging
    within the limit succeeds.
    """
    bda = ctx.client("bedrock-data-automation")
    raw = _raw_client(ctx)
    name = ctx.unique_name("sim2real-bda-bp-quota")
    arn = bda.create_blueprint(blueprintName=name, type="DOCUMENT", schema=_SCHEMA)["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))

    too_many_tags = [{"key": f"k{i}", "value": f"v{i}"} for i in range(201)]
    code, message = _error_code(lambda: raw.tag_resource(resourceARN=arn, tags=too_many_tags))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "1 validation error detected: Value at 'tags' failed to satisfy constraint: "
        "Member must have length less than or equal to 200"
    ), f"unexpected message: {message!r}"

    # Effect absent: no tags landed on the resource from the rejected call.
    assert bda.list_tags_for_resource(resourceARN=arn)["tags"] == []

    # Positive control: tagging with a valid count succeeds.
    bda.tag_resource(resourceARN=arn, tags=[{"key": "team", "value": "sim2real"}])
    tags = {t["key"]: t["value"] for t in bda.list_tags_for_resource(resourceARN=arn)["tags"]}
    assert tags == {"team": "sim2real"}


def _raw_client(ctx):
    """A client with client-side parameter validation disabled, so the over-limit tag list is
    actually sent to the TARGET and the SERVER's own rejection is observed, instead of boto3
    raising a local ParamValidationError before any request is made (botocore's TagList shape
    for bedrock-data-automation already caps at max=200, so the default client can never
    exercise the server's own enforcement)."""
    from botocore.config import Config

    return ctx.client("bedrock-data-automation", config=Config(parameter_validation=False))


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
