"""put-overly-broad-resource-policy-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

_MANAGED_ONLY_MESSAGE = "Resource policies are only supported for MANAGED type knowledge bases."
CHECK = "put-overly-broad-resource-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on an S3 Vectors knowledge base gets ValidationException "Resource policies are
    only supported for MANAGED type knowledge bases" for a wildcard-principal and an account-scoped
    policy alike, and GetResourcePolicy then answers the same refusal."""
    bedrock_agent = ctx.client("bedrock-agent")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_arn = _create_kb_role(ctx)
    kb_id, kb_name = _create_kb(ctx, role_arn)
    kb_status = _wait_kb_status(ctx, kb_id, {"ACTIVE", "FAILED"})
    assert kb_status == "ACTIVE", (
        f"positive control failed: knowledge base {kb_id} never became ACTIVE, last status {kb_status!r}"
    )
    kb_arn = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["knowledgeBaseArn"]

    broad_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "OverlyBroad",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "bedrock:GetKnowledgeBase",
                    "Resource": kb_arn,
                }
            ],
        }
    )
    broad_code, broad_message = _error(
        lambda: bedrock_agent.put_resource_policy(resourceArn=kb_arn, policy=broad_policy)
    )
    assert broad_code == "ValidationException", (
        f"expected ValidationException for a wildcard-principal policy, got {broad_code}: {broad_message}"
    )
    assert broad_message == _MANAGED_ONLY_MESSAGE, broad_message

    # Same refusal for a properly-scoped policy is the discriminating control: it proves the
    # block is about the store type, not about the wildcard principal specifically.
    scoped_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ScopedToAccount",
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": "bedrock:GetKnowledgeBase",
                    "Resource": kb_arn,
                }
            ],
        }
    )
    scoped_code, scoped_message = _error(
        lambda: bedrock_agent.put_resource_policy(resourceArn=kb_arn, policy=scoped_policy)
    )
    assert scoped_code == "ValidationException", (
        f"expected the identical MANAGED-type-only refusal for a properly-scoped policy, "
        f"got {scoped_code}: {scoped_message}"
    )
    assert scoped_message == _MANAGED_ONLY_MESSAGE, scoped_message

    # Effect absent: neither attempt stored anything. GetResourcePolicy on a knowledge base ARN
    # with no policy attached returns ValidationException (empirically, not ResourceNotFoundException).
    absent_code, absent_message = _error(lambda: bedrock_agent.get_resource_policy(resourceArn=kb_arn))
    assert absent_code == "ValidationException", absent_code
    assert absent_message == _MANAGED_ONLY_MESSAGE, absent_message


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
    role_name = ctx.unique_name("sim2real-bkb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-bkb-pol-")
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


def _call_with_role_propagation_retry(fn, *, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None
    raise last_err


def _create_s3_vectors_storage(ctx):
    """A real, quickly-provisioned (synchronous, no cluster) S3 Vectors bucket + index so
    CreateKnowledgeBase's storage-configuration validation - which checks the referenced
    store actually exists - passes."""
    s3vectors = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-bkb-vb").lower().replace("_", "-")[:63]
    index_name = ctx.unique_name("sim2real-bkb-idx").lower().replace("_", "-")[:63]

    s3vectors.create_vector_bucket(vectorBucketName=bucket_name)
    ctx.on_cleanup(lambda: _safe(lambda: s3vectors.delete_vector_bucket(vectorBucketName=bucket_name)))
    bucket_arn = s3vectors.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]["vectorBucketArn"]

    index_arn = s3vectors.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=1536,  # amazon.titan-embed-text-v1 output dimension
        distanceMetric="cosine",
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


def _create_kb(ctx, role_arn):
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-bkb-")
    storage_configuration = _create_s3_vectors_storage(ctx)

    def _create():
        return bedrock_agent.create_knowledge_base(
            name=name,
            roleArn=role_arn,
            knowledgeBaseConfiguration={
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {
                    "embeddingModelArn": f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.titan-embed-text-v1"
                },
            },
            storageConfiguration=storage_configuration,
        )["knowledgeBase"]

    # IAM role propagation before Bedrock assumes it -- retry past the transient
    # AccessDenied/ValidationException window instead of guessing a fixed sleep.
    kb = _call_with_role_propagation_retry(_create)
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
