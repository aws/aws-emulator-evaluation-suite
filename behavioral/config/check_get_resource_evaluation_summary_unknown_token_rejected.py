"""get-resource-evaluation-summary-unknown-token-rejected."""
from __future__ import annotations

import json
import secrets
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resource-evaluation-summary-unknown-token-rejected"
GROUP = "error-semantics"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceEvaluationSummary for a real ResourceEvaluationId returns the evaluation, but
    for an unknown id it raises ResourceNotFoundException rather than an empty success."""
    config = ctx.client("config")

    resource_id = ctx.unique_name("sim2real-eval-")
    details = {
        "ResourceId": resource_id,
        "ResourceType": "AWS::S3::Bucket",
        "ResourceConfiguration": json.dumps({"BucketName": resource_id}),
        "ResourceConfigurationSchemaType": "CFN_RESOURCE_SCHEMA",
    }
    started = config.start_resource_evaluation(
        ResourceDetails=details,
        EvaluationMode="PROACTIVE",
        ClientToken=secrets.token_hex(32),
    )
    real_id = started["ResourceEvaluationId"]

    # Positive control: a real evaluation id resolves successfully.
    summary = config.get_resource_evaluation_summary(ResourceEvaluationId=real_id)
    assert summary["ResourceEvaluationId"] == real_id, (
        f"expected ResourceEvaluationId={real_id!r}, got {summary.get('ResourceEvaluationId')!r}"
    )
    assert summary["EvaluationMode"] == "PROACTIVE", (
        f"expected EvaluationMode=PROACTIVE, got {summary.get('EvaluationMode')!r}"
    )

    # Break exactly one thing: query a syntactically valid but never-issued evaluation id.
    fake_id = str(uuid.uuid4())
    code, message = _error(lambda: config.get_resource_evaluation_summary(ResourceEvaluationId=fake_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Provided ResourceEvaluationId {fake_id} not found.", message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(
        f"real AWS rejects GetResourceEvaluationSummary on an unknown id, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
