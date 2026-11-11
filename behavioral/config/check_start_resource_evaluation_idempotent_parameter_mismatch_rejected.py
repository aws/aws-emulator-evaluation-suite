"""start-resource-evaluation-idempotent-parameter-mismatch-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-resource-evaluation-idempotent-parameter-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartResourceEvaluation repeated with the same ClientToken and parameters returns the same
    ResourceEvaluationId; with different parameters it fails with IdempotentParameterMismatch and its
    exact message, and the evaluation keeps the first ResourceId."""
    config = ctx.client("config")
    token = _client_token()

    resource_details_1 = {
        "ResourceId": ctx.unique_name("sim2real-bucket-"),
        "ResourceType": "AWS::S3::Bucket",
        "ResourceConfiguration": json.dumps(
            {"BucketName": ctx.unique_name("sim2real-cfg-bucket-")}
        ),
        "ResourceConfigurationSchemaType": "CFN_RESOURCE_SCHEMA",
    }

    first = config.start_resource_evaluation(
        ResourceDetails=resource_details_1,
        EvaluationMode="PROACTIVE",
        ClientToken=token,
    )
    evaluation_id = first["ResourceEvaluationId"]

    # Positive control: replaying the exact same request with the same token is
    # idempotent and returns the same evaluation, not a new one.
    replay = config.start_resource_evaluation(
        ResourceDetails=resource_details_1,
        EvaluationMode="PROACTIVE",
        ClientToken=token,
    )
    assert replay["ResourceEvaluationId"] == evaluation_id, (
        f"idempotent replay returned {replay['ResourceEvaluationId']!r}, "
        f"expected the original {evaluation_id!r}"
    )

    # Break exactly one thing: reuse the same token with a different ResourceId.
    resource_details_2 = dict(resource_details_1)
    resource_details_2["ResourceId"] = ctx.unique_name("sim2real-bucket-other-")

    code, message = _error(
        lambda: config.start_resource_evaluation(
            ResourceDetails=resource_details_2,
            EvaluationMode="PROACTIVE",
            ClientToken=token,
        )
    )
    assert code == "IdempotentParameterMismatch", (
        f"expected IdempotentParameterMismatch, got {code!r}"
    )
    expected_message = (
        f"The request inputs are not associated with the supplied client token {token}. "
        "You are using the same client token with one or more different parameters. "
        "Specify a new client token with the parameter changes and try again."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # The effect is absent: the original evaluation is unchanged, still referring to
    # the original resource, not the mismatched one.
    summary = config.get_resource_evaluation_summary(ResourceEvaluationId=evaluation_id)
    assert summary["ResourceDetails"]["ResourceId"] == resource_details_1["ResourceId"], (
        f"original evaluation {evaluation_id!r} now refers to "
        f"{summary['ResourceDetails']['ResourceId']!r}, expected it unchanged at "
        f"{resource_details_1['ResourceId']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING the mismatched replay real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects a ClientToken reuse with mismatched parameters, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _client_token() -> str:
    # ClientToken must be between 64 and 256 ASCII characters.
    return f"sim2real-token-{uuid.uuid4().hex}-{uuid.uuid4().hex}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
