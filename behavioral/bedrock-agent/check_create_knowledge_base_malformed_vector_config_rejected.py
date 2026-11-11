"""create-knowledge-base-malformed-vector-config-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-knowledge-base-malformed-vector-config-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKnowledgeBase of type VECTOR with no vector or storage configuration gets ValidationException
    "You must provide a storage configuration if you create a VECTOR knowledge base." and creates no
    knowledge base."""
    bedrock_agent = ctx.client("bedrock-agent")
    role_arn = _create_kb_role(ctx)

    bad_name = ctx.unique_name("sim2real-bkb-bad-")
    code, message = _error(
        lambda: bedrock_agent.create_knowledge_base(
            name=bad_name,
            roleArn=role_arn,
            knowledgeBaseConfiguration={"type": "VECTOR"},  # missing required nested vector config
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "You must provide a storage configuration if you create a VECTOR knowledge base.", message

    # Effect absent: no knowledge base with that name exists.
    kbs = bedrock_agent.list_knowledge_bases()["knowledgeBaseSummaries"]
    assert not any(kb["name"] == bad_name for kb in kbs), (
        f"expected no knowledge base named {bad_name!r} after the rejected create, "
        f"found one in list_knowledge_bases"
    )

    # Positive control: a well-formed VECTOR config is accepted for (async) processing, even
    # though the backing store referenced here is not actually provisioned.
    ok_kb_id, ok_name = _create_kb(ctx, role_arn)
    fetched = bedrock_agent.get_knowledge_base(knowledgeBaseId=ok_kb_id)["knowledgeBase"]
    assert fetched["name"] == ok_name, f"expected fetched name {ok_name!r}, got {fetched['name']!r}"


from botocore.exceptions import ClientError  # noqa: E402


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-bkb-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["bedrock:InvokeModel"],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3vectors:*"],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_s3_vectors_storage(ctx):
    """A real, quickly-provisioned (synchronous, no cluster) S3 Vectors bucket + index so
    CreateKnowledgeBase's storage-configuration validation - which checks the referenced
    store actually exists - passes for the "well-formed" positive control."""
    s3vectors = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-bkb-vb").lower().replace("_", "-")[:63]
    index_name = ctx.unique_name("sim2real-bkb-idx").lower().replace("_", "-")[:63]

    s3vectors.create_vector_bucket(vectorBucketName=bucket_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe(lambda: s3vectors.delete_vector_bucket(vectorBucketName=bucket_name)))
    bucket_arn = s3vectors.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]["vectorBucketArn"]

    index_arn = s3vectors.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=1536,  # amazon.titan-embed-text-v1 output dimension
        distanceMetric="cosine",
        tags={"sim2real": CHECK},
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


def _create_knowledge_base_with_role_propagation_retry(bedrock_agent, timeout_s=60.0, interval_s=5.0, **kwargs):
    """CreateKnowledgeBase validates roleArn's trust policy against IAM, which can lag a
    few seconds behind a just-created role/policy. Retry the create itself on that
    specific transient signal instead of sleeping first and hoping; any other error is a
    real defect and must not be swallowed."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return bedrock_agent.create_knowledge_base(**kwargs)
        except ClientError as exc:
            message = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] == "ValidationException" and "role" in message.lower():
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"create_knowledge_base never succeeded (role propagation timeout): {last_exc}")


def _create_kb(ctx, role_arn):
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-bkb-")
    kb = _create_knowledge_base_with_role_propagation_retry(
        bedrock_agent,
        name=name,
        roleArn=role_arn,
        knowledgeBaseConfiguration={
            "type": "VECTOR",
            "vectorKnowledgeBaseConfiguration": {
                "embeddingModelArn": f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.titan-embed-text-v1"
            },
        },
        storageConfiguration=_create_s3_vectors_storage(ctx),
        tags={"sim2real": CHECK},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _delete_kb_once_settled(bedrock_agent, kb_id))
    return kb_id, name


def _delete_kb_once_settled(bedrock_agent, kb_id, timeout_s=180.0, interval_s=5.0):
    """DeleteKnowledgeBase refuses a knowledge base still CREATING, so wait (bounded) for it to
    leave CREATING before deleting it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status != "CREATING":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"knowledge base {kb_id} still CREATING after {timeout_s}s")
        time.sleep(interval_s)
    _safe(lambda: bedrock_agent.delete_knowledge_base(knowledgeBaseId=kb_id))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
