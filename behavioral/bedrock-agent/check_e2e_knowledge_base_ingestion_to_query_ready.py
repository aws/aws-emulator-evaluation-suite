"""e2e-knowledge-base-ingestion-to-query-ready."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-knowledge-base-ingestion-to-query-ready"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock-agent"]

EMBEDDING_MODEL = "amazon.titan-embed-text-v1"
EMBEDDING_DIMENSION = 1536


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pushed CUSTOM doc and a crawled S3 doc are both ingested; an ingestion job completes; ListKnowledgeBaseDocuments confirms both indexed."""
    bedrock_agent = ctx.client("bedrock-agent")
    s3 = ctx.client("s3")
    account_id, partition = _caller_identity(ctx)

    bucket_name = ctx.unique_name("sim2real-e2eingest-s3-").lower()
    if ctx.region == "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint that names the default
        # region (us-east-1); every other region requires it.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _safe(lambda: _empty_and_delete_bucket(ctx, bucket_name)))
    bucket_arn = f"arn:{partition}:s3:::{bucket_name}"

    kb_id = _create_minimal_kb(ctx, account_id, partition, bucket_arn)
    ctx.on_cleanup(lambda: _safe(lambda: bedrock_agent.delete_knowledge_base(knowledgeBaseId=kb_id)))

    ds_custom_id = bedrock_agent.create_data_source(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-e2eingest-custom-ds-"),
        dataSourceConfiguration={"type": "CUSTOM"},
    )["dataSource"]["dataSourceId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: bedrock_agent.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_custom_id))
    )
    _wait_data_source_status(ctx, kb_id, ds_custom_id, {"AVAILABLE", "FAILED"})

    ds_s3_id = bedrock_agent.create_data_source(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-e2eingest-s3-ds-"),
        dataSourceConfiguration={"type": "S3", "s3Configuration": {"bucketArn": bucket_arn}},
    )["dataSource"]["dataSourceId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: bedrock_agent.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_s3_id))
    )
    _wait_data_source_status(ctx, kb_id, ds_s3_id, {"AVAILABLE", "FAILED"})

    # Direct push path: IngestKnowledgeBaseDocuments only supports CUSTOM data sources.
    doc_identifier = ctx.unique_name("sim2real-doc-")
    bedrock_agent.ingest_knowledge_base_documents(
        knowledgeBaseId=kb_id,
        dataSourceId=ds_custom_id,
        documents=[
            {
                "content": {
                    "dataSourceType": "CUSTOM",
                    "custom": {
                        "customDocumentIdentifier": {"id": doc_identifier},
                        "sourceType": "IN_LINE",
                        "inlineContent": {
                            "type": "TEXT",
                            "textContent": {
                                "data": (
                                    "Amazon Bedrock Knowledge Bases retrieve relevant chunks of "
                                    "text at runtime to ground an agent's responses."
                                )
                            },
                        },
                    },
                }
            }
        ],
    )

    status_after_push = _wait_document_status(ctx, kb_id, ds_custom_id, doc_identifier, timeout_s=300.0)
    assert status_after_push == "INDEXED", f"pushed document never reached INDEXED, last status={status_after_push}"

    # Crawl path: StartIngestionJob only supports S3 (and other crawl-based) data sources, not CUSTOM.
    doc_key = "sim2real-doc.txt"
    s3.put_object(
        Bucket=bucket_name,
        Key=doc_key,
        Body=b"Amazon Bedrock Knowledge Bases crawl S3 objects and index them for retrieval.",
    )

    job = bedrock_agent.start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_s3_id)["ingestionJob"]
    job_id = job["ingestionJobId"]
    final_job = _wait_ingestion_job(ctx, kb_id, ds_s3_id, job_id, timeout_s=300.0)
    assert final_job["status"] == "COMPLETE", f"ingestion job never completed, last status={final_job['status']}"
    assert final_job["statistics"]["numberOfDocumentsScanned"] >= 1, (
        f"expected the crawl to scan at least the one S3 object written, "
        f"got statistics={final_job['statistics']}"
    )

    custom_docs = bedrock_agent.list_knowledge_base_documents(knowledgeBaseId=kb_id, dataSourceId=ds_custom_id)[
        "documentDetails"
    ]
    matching = [d for d in custom_docs if d["identifier"].get("custom", {}).get("id") == doc_identifier]
    assert len(matching) == 1, f"expected exactly one listed CUSTOM document for {doc_identifier}, got {len(matching)}"
    assert matching[0]["status"] == "INDEXED", f"expected INDEXED, got {matching[0]['status']}"

    s3_docs = bedrock_agent.list_knowledge_base_documents(knowledgeBaseId=kb_id, dataSourceId=ds_s3_id)[
        "documentDetails"
    ]
    assert len(s3_docs) >= 1, "expected the crawled S3 document to be listed after StartIngestionJob completed"
    assert any(d["status"] == "INDEXED" for d in s3_docs), f"no S3 document reached INDEXED: {s3_docs}"

    # Explicit lifecycle teardown, verified before the safety-net cleanup registered above.
    bedrock_agent.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_custom_id)
    bedrock_agent.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_s3_id)
    bedrock_agent.delete_knowledge_base(knowledgeBaseId=kb_id)


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-e2eingest"}


def _caller_identity(ctx):
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    return identity["Account"], identity["Arn"].split(":")[1]


def _empty_and_delete_bucket(ctx, bucket_name):
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket_name)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket_name)


def _create_trust_role(ctx, role_name, source_arn, statements, account_id):
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": source_arn},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline-permissions",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-permissions")))
    # No fixed propagation sleep: _create_kb_with_retry bounds IAM's eventual
    # consistency by retrying CreateKnowledgeBase on AccessDeniedException up to its
    # own deadline, so the role is used as soon as it exists and the wait is bounded
    # by that retry loop rather than by a blind sleep here.
    return role_arn


def _create_minimal_kb(ctx, account_id, partition, bucket_arn):
    s3vectors = ctx.client("s3vectors")
    ctx.client("bedrock-agent")

    bucket_name = ctx.unique_name("sim2real-e2eingest-vec-").lower()
    index_name = ctx.unique_name("sim2real-e2eingest-idx-").lower()

    s3vectors.create_vector_bucket(vectorBucketName=bucket_name, tags=_mgmt_tags())
    ctx.on_cleanup(lambda: _safe(lambda: s3vectors.delete_vector_bucket(vectorBucketName=bucket_name)))
    s3vectors.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=EMBEDDING_DIMENSION,
        distanceMetric="cosine",
        tags=_mgmt_tags(),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: s3vectors.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    )

    vector_bucket_arn = f"arn:{partition}:s3vectors:{ctx.region}:{account_id}:bucket/{bucket_name}"
    index_arn = f"{vector_bucket_arn}/index/{index_name}"

    kb_role_arn = _create_trust_role(
        ctx,
        role_name=ctx.unique_name("sim2real-e2eingest-role-"),
        source_arn=f"arn:{partition}:bedrock:{ctx.region}:{account_id}:knowledge-base/*",
        statements=[
            {
                "Effect": "Allow",
                "Action": "bedrock:InvokeModel",
                "Resource": f"arn:{partition}:bedrock:{ctx.region}::foundation-model/{EMBEDDING_MODEL}",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3vectors:GetIndex",
                    "s3vectors:PutVectors",
                    "s3vectors:GetVectors",
                    "s3vectors:QueryVectors",
                    "s3vectors:DeleteVectors",
                    "s3vectors:ListVectors",
                ],
                "Resource": [vector_bucket_arn, index_arn],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            },
        ],
        account_id=account_id,
    )

    kb_id = _create_kb_with_retry(ctx, kb_role_arn, vector_bucket_arn, index_arn, index_name)
    _wait_kb_status(ctx, kb_id, {"ACTIVE", "FAILED"})
    return kb_id


def _create_kb_with_retry(ctx, role_arn, vector_bucket_arn, index_arn, index_name, timeout_s=90.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return bedrock_agent.create_knowledge_base(
                name=ctx.unique_name("sim2real-e2eingest-kb-"),
                roleArn=role_arn,
                knowledgeBaseConfiguration={
                    "type": "VECTOR",
                    "vectorKnowledgeBaseConfiguration": {
                        "embeddingModelArn": f"arn:aws:bedrock:{ctx.region}::foundation-model/{EMBEDDING_MODEL}"
                    },
                },
                storageConfiguration={
                    "type": "S3_VECTORS",
                    "s3VectorsConfiguration": {
                        "vectorBucketArn": vector_bucket_arn,
                        "indexArn": index_arn,
                    },
                },
                tags=_mgmt_tags(),
            )["knowledgeBase"]["knowledgeBaseId"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            time.sleep(5)
    raise last_exc


def _wait_kb_status(ctx, kb_id, target_statuses, timeout_s=180.0, interval_s=5.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    return status


def _wait_data_source_status(ctx, kb_id, ds_id, target_statuses, timeout_s=120.0, interval_s=5.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = bedrock_agent.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]["status"]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    return status


def _wait_document_status(ctx, kb_id, ds_id, doc_identifier, timeout_s=300.0, interval_s=10.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        docs = bedrock_agent.get_knowledge_base_documents(
            knowledgeBaseId=kb_id,
            dataSourceId=ds_id,
            documentIdentifiers=[{"dataSourceType": "CUSTOM", "custom": {"id": doc_identifier}}],
        )["documentDetails"]
        if docs:
            status = docs[0]["status"]
            if status in ("INDEXED", "FAILED", "IGNORED"):
                return status
        time.sleep(interval_s)
    return status


def _wait_ingestion_job(ctx, kb_id, ds_id, job_id, timeout_s=300.0, interval_s=10.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    job = None
    while time.monotonic() < deadline:
        job = bedrock_agent.get_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id)[
            "ingestionJob"
        ]
        if job["status"] in ("COMPLETE", "FAILED"):
            return job
        time.sleep(interval_s)
    return job


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket",
            "NoSuchEntity",
            "NoSuchKey",
            "NotFoundException",
            "ResourceNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

