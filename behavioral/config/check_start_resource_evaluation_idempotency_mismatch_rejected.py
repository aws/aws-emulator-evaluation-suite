"""start-resource-evaluation-idempotency-mismatch-rejected."""
from __future__ import annotations

import json
import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-resource-evaluation-idempotency-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartResourceEvaluation repeated with the same ClientToken and parameters returns the same
    ResourceEvaluationId; with different parameters it fails with IdempotentParameterMismatch and its
    exact message, and the stored ResourceDetails keep the original ResourceId."""
    config = ctx.client("config")

    resource_id = ctx.unique_name("sim2real-eval-")
    details = {
        "ResourceId": resource_id,
        "ResourceType": "AWS::S3::Bucket",
        "ResourceConfiguration": json.dumps({"BucketName": resource_id}),
        "ResourceConfigurationSchemaType": "CFN_RESOURCE_SCHEMA",
    }
    token = secrets.token_hex(32)  # 64 chars, within the 64-256 ClientToken length bound

    first = config.start_resource_evaluation(
        ResourceDetails=details, EvaluationMode="PROACTIVE", ClientToken=token
    )
    first_id = first["ResourceEvaluationId"]

    # Positive control: replaying the SAME token with the SAME parameters is idempotent.
    replay = config.start_resource_evaluation(
        ResourceDetails=details, EvaluationMode="PROACTIVE", ClientToken=token
    )
    assert replay["ResourceEvaluationId"] == first_id, "idempotent replay returned a different evaluation id"

    # Break exactly one thing: reuse the SAME token with a DIFFERENT ResourceId.
    mismatched_details = dict(details)
    mismatched_details["ResourceId"] = resource_id + "-different"
    code, message = _error(
        lambda: config.start_resource_evaluation(
            ResourceDetails=mismatched_details, EvaluationMode="PROACTIVE", ClientToken=token
        )
    )
    assert code == "IdempotentParameterMismatch", f"expected IdempotentParameterMismatch, got {code}"
    expected_message = (
        f"The request inputs are not associated with the supplied client token {token}. "
        "You are using the same client token with one or more different parameters. "
        "Specify a new client token with the parameter changes and try again."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Independent read at the destination: the rejected mismatch must not have touched the
    # evaluation the token already owns — it still reflects the ORIGINAL ResourceId, not the
    # mismatched one.
    summary = config.get_resource_evaluation_summary(ResourceEvaluationId=first_id)
    stored_resource_id = summary["ResourceDetails"]["ResourceId"]
    assert stored_resource_id == resource_id, (
        f"rejected mismatch corrupted the original evaluation: expected ResourceId "
        f"{resource_id!r}, found {stored_resource_id!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects a ClientToken replay with mismatched parameters, but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
