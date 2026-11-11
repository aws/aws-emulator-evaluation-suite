"""lambda-bedrock-agent-missing-retrieve-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-bedrock-agent-missing-retrieve-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]

EMBED_MODEL_ID = "amazon.titan-embed-text-v2:0"
EMBED_DIM = 1024
SECRET = "ZX-9921-QRT"
DOC_TEXT = (
    f"Project Falcon operations manual. The secret launch code for project Falcon is {SECRET}. "
    "Do not share this code outside the launch team."
)

LAMBDA_CODE = """
import json
import boto3

def handler(event, context):
    client = boto3.client("bedrock-agent-runtime")
    try:
        resp = client.retrieve(
            knowledgeBaseId=event["kb_id"],
            retrievalQuery={"text": event["query"]},
        )
        texts = [r["content"]["text"] for r in resp.get("retrievalResults", [])]
        return {"ok": True, "texts": texts}
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        return {"ok": False, "error_code": code}
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role lacking bedrock:Retrieve gets AccessDeniedException and no KB retrieval occurs."""
    bucket_arn = _create_source_bucket_with_doc(ctx, DOC_TEXT)
    vector_bucket_arn, index_arn, index_name = _create_vector_index(ctx)
    kb_role_arn = _create_role(
        ctx,
        "bedrock.amazonaws.com",
        [
            {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": _fm_arn(ctx, EMBED_MODEL_ID)},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": [bucket_arn, f"{bucket_arn}/*"]},
            {"Effect": "Allow", "Action": "s3vectors:*", "Resource": "*"},
        ],
    )
    kb_id = _create_knowledge_base(ctx, kb_role_arn, vector_bucket_arn, index_arn)
    _create_data_source_and_ingest(ctx, kb_id, bucket_arn)

    # Deny role: no bedrock permission at all.
    deny_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
    )
    deny_fn = _create_lambda(ctx, deny_role_arn, LAMBDA_CODE)

    # Allow role: adds bedrock:Retrieve -- the in-file positive control.
    allow_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        [
            {"Effect": "Allow", "Action": "bedrock:Retrieve", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    )
    allow_fn = _create_lambda(ctx, allow_role_arn, LAMBDA_CODE)

    query_args = {"kb_id": kb_id, "query": "What is the secret launch code for project Falcon?"}

    denied = _invoke_lambda_json(ctx, deny_fn, query_args)
    assert denied["ok"] is False, denied
    assert denied["error_code"] == "AccessDeniedException"
    assert "texts" not in denied  # no retrieval ever executed

    allowed = _invoke_lambda_json(ctx, allow_fn, query_args)
    assert allowed["ok"] is True, allowed
    assert any(SECRET in t for t in allowed["texts"]), allowed["texts"]


# ===== helpers =====


def _fm_arn(ctx, model_id: str) -> str:
    return f"arn:aws:bedrock:{ctx.region}::foundation-model/{model_id}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_role(ctx, trust_service: str, statements: list) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return role_arn


def _create_lambda(ctx, role_arn: str, code: str, timeout: int = 60) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    ctx.on_cleanup(lambda: _delete_lambda_log_group(ctx, name))
    # Until IAM propagates the new role, CreateFunction answers InvalidParameterValueException
    # "... cannot be assumed by Lambda"; retry exactly that, polling to a deadline.
    deadline = time.monotonic() + 75.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=timeout,
                MemorySize=256,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            if "cannot be assumed" not in str(e) or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=90,
        interval_s=3,
    )
    return name


def _invoke_lambda_json(ctx, name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse", Payload=json.dumps(payload).encode())
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda function error: {body}")
    return body


def _create_source_bucket_with_doc(ctx, doc_text: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-kbsrc-")
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a pinned resource.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    s3.put_object(Bucket=bucket, Key="doc.txt", Body=doc_text.encode("utf-8"))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="doc.txt"))
    return f"arn:aws:s3:::{bucket}"


def _create_vector_index(ctx) -> tuple[str, str, str]:
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-vb-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    bucket_arn = s3v.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]["vectorBucketArn"]
    index_name = ctx.unique_name("sim2real-vi-")
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=EMBED_DIM,
        distanceMetric="cosine",
        tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    index_arn = s3v.get_index(vectorBucketName=bucket_name, indexName=index_name)["index"]["indexArn"]
    return bucket_arn, index_arn, index_name


def _create_knowledge_base(ctx, kb_role_arn: str, vector_bucket_arn: str, index_arn: str) -> str:
    ba = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-kb-")
    last_exc = None
    for _ in range(10):
        try:
            kb_id = ba.create_knowledge_base(
                name=name,
                roleArn=kb_role_arn,
                knowledgeBaseConfiguration={
                    "type": "VECTOR",
                    "vectorKnowledgeBaseConfiguration": {"embeddingModelArn": _fm_arn(ctx, EMBED_MODEL_ID)},
                },
                storageConfiguration={
                    "type": "S3_VECTORS",
                    "s3VectorsConfiguration": {
                        "vectorBucketArn": vector_bucket_arn,
                        "indexArn": index_arn,
                    },
                },
                tags={"sim2real:managed": "true"},
            )["knowledgeBase"]["knowledgeBaseId"]
            break
        except ba.exceptions.ValidationException as e:
            last_exc = e
            time.sleep(5)
    else:
        raise last_exc
    ctx.on_cleanup(lambda: ba.delete_knowledge_base(knowledgeBaseId=kb_id))
    status = _poll_until(
        lambda: ba.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    if status != "ACTIVE":
        raise AssertionError(f"knowledge base failed to become active: {status}")
    return kb_id


def _create_data_source_and_ingest(ctx, kb_id: str, bucket_arn: str) -> str:
    ba = ctx.client("bedrock-agent")
    ds_name = ctx.unique_name("sim2real-ds-")
    ds_id = ba.create_data_source(
        knowledgeBaseId=kb_id,
        name=ds_name,
        dataSourceConfiguration={"type": "S3", "s3Configuration": {"bucketArn": bucket_arn}},
    )["dataSource"]["dataSourceId"]
    ctx.on_cleanup(lambda: ba.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id))
    status = _poll_until(
        lambda: ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=60,
        interval_s=3,
    )
    if status != "AVAILABLE":
        raise AssertionError(f"data source failed to become available: {status}")
    job_id = ba.start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id)["ingestionJob"]["ingestionJobId"]
    job_status = _poll_until(
        lambda: ba.get_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id)[
            "ingestionJob"
        ]["status"],
        lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=300,
        interval_s=5,
    )
    if job_status != "COMPLETE":
        raise AssertionError(f"ingestion job failed: {job_status}")
    return ds_id


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
