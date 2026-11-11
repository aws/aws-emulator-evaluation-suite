"""get-blueprint-nonexistent-arn-not-found."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "get-blueprint-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBlueprint on a syntactically valid but never-created blueprintArn fails with
    ResourceNotFoundException, while the identical call against a real, just-created Blueprint
    succeeds."""
    bda = ctx.client("bedrock-data-automation")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: GetBlueprint against a real Blueprint succeeds, so the account and
    # credentials are otherwise healthy for this operation.
    name = ctx.unique_name("sim2real-bp-")
    real_arn = bda.create_blueprint(
        blueprintName=name,
        type="DOCUMENT",
        schema=_blueprint_schema(),
        tags=[{"key": "purpose", "value": "sim2real"}],
    )["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=real_arn))
    fetched = bda.get_blueprint(blueprintArn=real_arn)["blueprint"]
    assert fetched["blueprintArn"] == real_arn, f"expected {real_arn!r}, got {fetched['blueprintArn']!r}"

    fake_id = uuid.uuid4().hex[:20]
    fake_arn = f"arn:aws:bedrock:{ctx.region}:{account_id}:blueprint/{fake_id}"

    code, message = _client_error(lambda: bda.get_blueprint(blueprintArn=fake_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} ({message})"
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


def _client_error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
