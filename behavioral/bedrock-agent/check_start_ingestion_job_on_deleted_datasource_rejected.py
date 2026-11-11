"""start-ingestion-job-on-deleted-datasource-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "start-ingestion-job-on-deleted-datasource-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartIngestionJob against a data source that has already been deleted is rejected with
    ResourceNotFoundException instead of being silently accepted and left stalled forever."""
    bedrock_agent = ctx.client("bedrock-agent")

    kb_role_arn = _create_kb_role(ctx)
    kb_id, kb_name = _create_kb(ctx, kb_role_arn)
    bucket_name = _create_s3_bucket(ctx)

    ds = bedrock_agent.create_data_source(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-bds-"),
        dataSourceConfiguration={"type": "S3", "s3Configuration": {"bucketArn": f"arn:aws:s3:::{bucket_name}"}},
    )["dataSource"]
    ds_id = ds["dataSourceId"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock_agent.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)))

    bedrock_agent.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)
    _wait_datasource_gone(ctx, kb_id, ds_id)

    code, message = _error(lambda: bedrock_agent.start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id))
    assert code == "ResourceNotFoundException", code
    assert message == f"DataSource with id {ds_id} is not found.", message

    # Effect absent: no ingestion job exists for the deleted data source.
    absent_code, absent_message = _error(lambda: bedrock_agent.list_ingestion_jobs(knowledgeBaseId=kb_id, dataSourceId=ds_id))
    assert absent_code == "ResourceNotFoundException", absent_code
    assert absent_message == f"DataSource with id {ds_id} is not found.", absent_message

    # Positive control: a live data source accepts StartIngestionJob.
    ds2 = bedrock_agent.create_data_source(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-bds-"),
        dataSourceConfiguration={"type": "S3", "s3Configuration": {"bucketArn": f"arn:aws:s3:::{bucket_name}"}},
    )["dataSource"]
    ds2_id = ds2["dataSourceId"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock_agent.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds2_id)))
    job_id = bedrock_agent.start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds2_id)["ingestionJob"]["ingestionJobId"]

    # Independent read at the destination: the job the mutating call claims to have
    # started is actually discoverable and runs to completion, not just echoed back.
    final = _wait_ingestion_job_terminal(ctx, kb_id, ds2_id, job_id)
    assert final == "COMPLETE", final


from botocore.exceptions import ClientError  # noqa: E402


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; an unexpected success
    raises, so a target that accepts what AWS refuses fails loudly rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_ingestion_job_terminal(ctx, kb_id, ds_id, job_id, timeout_s=300.0, interval_s=5.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = bedrock_agent.get_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )["ingestionJob"]["status"]
        if last in ("COMPLETE", "FAILED", "STOPPED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"ingestion job {job_id} never reached a terminal status, last={last}")


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
                    {"Effect": "Allow", "Action": ["bedrock:InvokeModel"], "Resource": "*"},
                    {"Effect": "Allow", "Action": ["s3vectors:*"], "Resource": "*"},
                    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"},
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
    bucket_name = ctx.unique_name("sim2real-bkb-vb").lower().replace("_", "-")[:63]
    index_name = ctx.unique_name("sim2real-bkb-idx").lower().replace("_", "-")[:63]

    s3vectors.create_vector_bucket(
        vectorBucketName=bucket_name, tags={"sim2real": CHECK}
    )
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


def _create_kb_with_role_propagation_retry(ctx, **kwargs):
    """A freshly created role/policy is eventually consistent; retry past the transient
    denial while Bedrock catches up, instead of guessing a fixed sleep."""
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + 30.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return bedrock_agent.create_knowledge_base(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_err = exc
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"create_knowledge_base never succeeded after role propagation wait: {last_err}")


def _create_kb(ctx, role_arn):
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-bkb-")
    kb = _create_kb_with_role_propagation_retry(
        ctx,
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
    ctx.on_cleanup(lambda: _safe(lambda: bedrock_agent.delete_knowledge_base(knowledgeBaseId=kb_id)))
    _wait_kb_status(ctx, kb_id, {"ACTIVE", "FAILED"})
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


def _create_s3_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bds-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _wait_datasource_gone(ctx, kb_id, ds_id, timeout_s=180.0, interval_s=5.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            bedrock_agent.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"data source {ds_id} was never removed")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
