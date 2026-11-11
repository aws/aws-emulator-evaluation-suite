"""invoke-blueprint-optimization-async-invalid-profile-rejected."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "invoke-blueprint-optimization-async-invalid-profile-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]

_SCHEMA = json.dumps(
    {
        "class": "OptimizeMe",
        "description": "optimization schema",
        "properties": {"x": {"type": "string", "inferenceType": "explicit", "instruction": "x"}},
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """InvokeBlueprintOptimizationAsync against a syntactically valid but nonexistent
    dataAutomationProfileArn is rejected with ValidationException, and the real Blueprint
    named in the call is left untouched."""
    bda = ctx.client("bedrock-data-automation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-bda-bp-opt")
    blueprint_arn = bda.create_blueprint(
        blueprintName=name,
        type="DOCUMENT",
        schema=_SCHEMA,
        tags=[{"key": "purpose", "value": "sim2real"}],
    )["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=blueprint_arn))

    bogus_profile_arn = f"arn:aws:bedrock:{ctx.region}:{account_id}:data-automation-profile/{uuid.uuid4().hex}"
    bogus_bucket = f"sim2real-nonexistent-{uuid.uuid4().hex[:12]}"

    code, message = _error_code(
        lambda: bda.invoke_blueprint_optimization_async(
            blueprint={"blueprintArn": blueprint_arn},
            samples=[
                {
                    "assetS3Object": {"s3Uri": f"s3://{bogus_bucket}/asset.pdf"},
                    "groundTruthS3Object": {"s3Uri": f"s3://{bogus_bucket}/ground-truth.json"},
                }
            ],
            outputConfiguration={"s3Object": {"s3Uri": f"s3://{bogus_bucket}/out.json"}},
            dataAutomationProfileArn=bogus_profile_arn,
        )
    )
    assert code == "ValidationException", f"unexpected code: {code}"
    assert message == "Request has invalid Data Automation Profile Arn", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )

    # Effect absent / unaffected: the real Blueprint referenced in the rejected call is untouched.
    fetched = bda.get_blueprint(blueprintArn=blueprint_arn)["blueprint"]
    assert fetched["blueprintArn"] == blueprint_arn, (
        f"blueprint identity changed after rejected call: expected {blueprint_arn}, got {fetched['blueprintArn']}"
    )
    assert fetched["schema"] == _SCHEMA, (
        f"blueprint schema mutated after rejected call: expected {_SCHEMA!r}, got {fetched['schema']!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
