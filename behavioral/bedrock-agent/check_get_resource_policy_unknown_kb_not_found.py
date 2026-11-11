"""get-resource-policy-unknown-kb-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-resource-policy-unknown-kb-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a nonexistent knowledge base ARN gets ResourceNotFoundException with the exact
    message, while a real S3 Vectors knowledge base gets ValidationException (managed-only), a
    different code."""
    sts = ctx.client("sts")
    bedrock_agent = ctx.client("bedrock-agent")
    account_id = sts.get_caller_identity()["Account"]

    role_arn = _create_kb_role(ctx)
    kb_id, _ = _create_kb(ctx, role_arn)
    _wait_kb_status(ctx, kb_id, {"ACTIVE", "FAILED"})
    kb_arn = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["knowledgeBaseArn"]

    live_code, live_message = _error(
        lambda: bedrock_agent.get_resource_policy(resourceArn=kb_arn)
    )
    assert live_code == "ValidationException", (
        f"expected ValidationException for a real, existing non-MANAGED knowledge base, "
        f"got {live_code}: {live_message}"
    )
    assert live_message == "Resource policies are only supported for MANAGED type knowledge bases.", live_message

    # Derive a well-formed but never-issued knowledge-base id from the real one (reverse it)
    # rather than fabricating one out of thin air, so the ARN stays within the probe identity's
    # resource scope.
    bogus_id = kb_id[::-1]
    assert bogus_id != kb_id, f"reversed id collided with the real id {kb_id!r}"
    bogus_arn = f"arn:aws:bedrock:{ctx.region}:{account_id}:knowledge-base/{bogus_id}"

    code, message = _error(lambda: bedrock_agent.get_resource_policy(resourceArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent knowledge base, got {code}"
    )
    assert message == f"KnowledgeBase with id {bogus_id} is not found.", message
    assert code != live_code, (
        "the nonexistent-resource and real-but-unsupported-type cases must not collapse onto "
        f"the same error code ({code!r})"
    )


from botocore.exceptions import ClientError  # noqa: E402


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; an unexpected success
    raises, so a target that accepts what AWS refuses fails loudly rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_kb_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-grpol-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-grpol-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["bedrock:InvokeModel"], "Resource": "*"},
                    {"Effect": "Allow", "Action": ["s3vectors:*"], "Resource": "*"},
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_s3_vectors_storage(ctx):
    """A real, quickly-provisioned (synchronous, no cluster) S3 Vectors bucket + index so
    CreateKnowledgeBase's storage-configuration validation - which checks the referenced
    store actually exists - passes."""
    s3vectors = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-grpol-vb").lower().replace("_", "-")[:63]
    index_name = ctx.unique_name("sim2real-grpol-idx").lower().replace("_", "-")[:63]

    s3vectors.create_vector_bucket(
        vectorBucketName=bucket_name, tags={"sim2real:check": CHECK}
    )
    ctx.on_cleanup(lambda: _safe(lambda: s3vectors.delete_vector_bucket(vectorBucketName=bucket_name)))
    bucket_arn = s3vectors.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]["vectorBucketArn"]

    index_arn = s3vectors.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=1536,  # amazon.titan-embed-text-v1 output dimension
        distanceMetric="cosine",
        tags={"sim2real:check": CHECK},
    )["indexArn"]
    ctx.on_cleanup(
        lambda: _safe(lambda: s3vectors.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    )

    return {
        "type": "S3_VECTORS",
        "s3VectorsConfiguration": {
            "vectorBucketArn": bucket_arn,
            "indexArn": index_arn,
        },
    }


def _retry_access_denied(fn, attempts: int = 10, delay: float = 6.0):
    """Bounded retry for the freshly created IAM role's trust/inline policy propagating to
    Bedrock, which surfaces as AccessDeniedException or ValidationException on the first
    CreateKnowledgeBase attempts."""
    last_error = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDeniedException", "ValidationException"):
                last_error = exc
                time.sleep(delay)
                continue
            raise
    raise last_error


def _create_kb(ctx, role_arn):
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-grpol-")
    kb = _retry_access_denied(
        lambda: bedrock_agent.create_knowledge_base(
            name=name,
            roleArn=role_arn,
            knowledgeBaseConfiguration={
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {
                    "embeddingModelArn": f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.titan-embed-text-v1"
                },
            },
            storageConfiguration=_create_s3_vectors_storage(ctx),
            tags={"sim2real:check": CHECK},
        )
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock_agent.delete_knowledge_base(knowledgeBaseId=kb_id)))
    return kb_id, name


def _wait_kb_status(ctx, kb_id, targets, timeout_s=180.0, interval_s=5.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"]
        if last in targets:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"knowledge base {kb_id} status never reached {targets}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
