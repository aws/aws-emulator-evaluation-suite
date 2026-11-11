"""lambda-bedrock-agent-retrieve-missing-permission-negative."""

from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-bedrock-agent-retrieve-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["bedrock-agent", "lambda", "opensearchserverless"]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role missing bedrock:Retrieve is denied Retrieve on an ingested knowledge base
    and gets no results, while a sibling Lambda whose role differs only by bedrock:Retrieve
    retrieves the ingested fact."""
    kb_id = _build_ready_knowledge_base(
        ctx,
        "The secret handshake phrase for the fidelity test suite is Quantum Marigold "
        "Seventeen.",
    )

    denied_role_arn, _ = _create_role(
        ctx,
        _LAMBDA_TRUST,
        [],
        "sim2real-lambdadenied-",
        managed_policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    denied_fn = _create_lambda(ctx, denied_role_arn, _RETRIEVE_HANDLER)
    denied_body = _invoke(
        ctx,
        denied_fn,
        {
            "region": ctx.region,
            "kb_id": kb_id,
            "query": "What is the secret handshake phrase?",
        },
    )
    assert denied_body["ok"] is False, denied_body
    assert denied_body["code"] == "AccessDeniedException", denied_body
    assert "results" not in denied_body, denied_body

    allowed_role_arn, _ = _create_role(
        ctx,
        _LAMBDA_TRUST,
        [{"Effect": "Allow", "Action": "bedrock:Retrieve", "Resource": "*"}],
        "sim2real-lambdaallowed-",
        managed_policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    allowed_fn = _create_lambda(ctx, allowed_role_arn, _RETRIEVE_HANDLER)
    # Bedrock reports the ingestion job COMPLETE once the source is read, but the OpenSearch
    # Serverless vector index still needs its own refresh interval before the ingested vector is
    # actually searchable -- a real, timed asynchrony, not a fixed sleep. Poll for it.
    allowed_deadline = time.monotonic() + 120
    allowed_body: dict = {}
    while time.monotonic() < allowed_deadline:
        allowed_body = _invoke(
            ctx,
            allowed_fn,
            {
                "region": ctx.region,
                "kb_id": kb_id,
                "query": "What is the secret handshake phrase?",
            },
        )
        if allowed_body.get("ok") and allowed_body.get("results"):
            break
        time.sleep(2)
    assert allowed_body["ok"] is True, allowed_body
    assert len(allowed_body["results"]) >= 1, allowed_body
    assert any("quantum marigold" in r.lower() for r in allowed_body["results"]), (
        allowed_body
    )


_RETRIEVE_HANDLER = """
import boto3

def handler(event, context):
    client = boto3.client("bedrock-agent-runtime", region_name=event["region"])
    try:
        resp = client.retrieve(
            knowledgeBaseId=event["kb_id"],
            retrievalQuery={"text": event["query"]},
            retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": 3}},
        )
        texts = [r["content"]["text"] for r in resp.get("retrievalResults", [])]
        return {"ok": True, "results": texts}
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        return {"ok": False, "code": code}
"""

_LAMBDA_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_BEDROCK_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _create_role(
    ctx, trust_policy_json, inline_statements, name_prefix, managed_policy_arn=None
):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy_json,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]

    def _cleanup():
        if managed_policy_arn:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    if managed_policy_arn:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    if inline_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": inline_statements}
            ),
        )
    return role["Arn"], role_name


def _zip_code(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _create_lambda(ctx, role_arn, src, env=None, timeout=120):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-lambda-fn-")
    zip_bytes = _zip_code(src)
    deadline = time.monotonic() + 90
    last_err: Any = None
    created = False
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real": CHECK},
            )
            created = True
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(5)
    if not created:
        raise AssertionError(f"lambda role never became assumable: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _invoke(ctx, fn_name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {raw!r}")
    return json.loads(raw)


def _caller_principal_arn(ctx) -> str:
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        parts = arn.split(":")
        account = parts[4]
        role_name = parts[5].split("/")[1]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _delete_collection(oss, collection_id: str, timeout_s: float = 600.0) -> None:
    """DeleteCollection is refused with ConflictException while the collection is still CREATING."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            oss.delete_collection(id=collection_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or "status" not in str(exc) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _build_ready_knowledge_base(ctx, ingest_text: str) -> str:
    oss = ctx.client("opensearchserverless")
    s3 = ctx.client("s3")
    bedrock_agent = ctx.client("bedrock-agent")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-kb-")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    kb_role_name = ctx.unique_name("sim2real-kbrole-")
    kb_role_arn = f"arn:aws:iam::{account_id}:role/{kb_role_name}"
    caller_arn = _caller_principal_arn(ctx)

    enc_policy = json.dumps(
        {
            "Rules": [
                {"ResourceType": "collection", "Resource": [f"collection/{name}"]}
            ],
            "AWSOwnedKey": True,
        }
    )
    oss.create_security_policy(name=name, type="encryption", policy=enc_policy)
    ctx.on_cleanup(lambda: oss.delete_security_policy(name=name, type="encryption"))

    net_policy = json.dumps(
        [
            {
                "Rules": [
                    {"ResourceType": "collection", "Resource": [f"collection/{name}"]},
                    {"ResourceType": "dashboard", "Resource": [f"collection/{name}"]},
                ],
                "AllowFromPublic": True,
            }
        ]
    )
    oss.create_security_policy(name=name, type="network", policy=net_policy)
    ctx.on_cleanup(lambda: oss.delete_security_policy(name=name, type="network"))

    access_policy = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "index",
                        "Resource": [f"index/{name}/*"],
                        "Permission": [
                            "aoss:CreateIndex",
                            "aoss:DeleteIndex",
                            "aoss:UpdateIndex",
                            "aoss:DescribeIndex",
                            "aoss:ReadDocument",
                            "aoss:WriteDocument",
                        ],
                    },
                    {
                        "ResourceType": "collection",
                        "Resource": [f"collection/{name}"],
                        "Permission": [
                            "aoss:CreateCollectionItems",
                            "aoss:DescribeCollectionItems",
                            "aoss:UpdateCollectionItems",
                        ],
                    },
                ],
                "Principal": [caller_arn, kb_role_arn],
            }
        ]
    )
    oss.create_access_policy(name=name, type="data", policy=access_policy)
    ctx.on_cleanup(lambda: oss.delete_access_policy(name=name, type="data"))

    resp = oss.create_collection(
        name=name, type="VECTORSEARCH", tags=[{"key": "sim2real", "value": CHECK}]
    )
    collection_id = resp["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _delete_collection(oss, collection_id))

    deadline = time.monotonic() + min(900, ctx.time_left() or 900)
    details = None
    while time.monotonic() < deadline:
        details = oss.batch_get_collection(ids=[collection_id])["collectionDetails"][0]
        if details["status"] == "ACTIVE":
            break
        if details["status"] == "FAILED":
            raise AssertionError("OpenSearch Serverless collection failed to create")
        time.sleep(2)
    if not details or details["status"] != "ACTIVE":
        raise AssertionError("OpenSearch Serverless collection never became ACTIVE")
    collection_arn = details["arn"]

    index_name = "sim2real-vectors"
    index_schema = {
        "settings": {"index.knn": True},
        "mappings": {
            "properties": {
                "vector": {
                    "type": "knn_vector",
                    "dimension": 1536,
                    "method": {"engine": "faiss", "name": "hnsw", "space_type": "l2"},
                },
                "text": {"type": "text"},
                "metadata": {"type": "text"},
            }
        },
    }
    deadline = time.monotonic() + 180
    created = False
    last_err: Any = None
    while time.monotonic() < deadline:
        try:
            oss.create_index(
                id=collection_id, indexName=index_name, indexSchema=index_schema
            )
            created = True
            break
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code not in ("AccessDeniedException", "ConflictException"):
                raise
            last_err = err
            time.sleep(2)
    if not created:
        raise AssertionError(
            f"failed to create OpenSearch Serverless vector index: {last_err}"
        )

    bucket_name = ctx.unique_name("sim2real-kb-docs-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _cleanup_bucket():
        try:
            s3.delete_object(Bucket=bucket_name, Key="doc.txt")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    s3.put_object(Bucket=bucket_name, Key="doc.txt", Body=ingest_text.encode())
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    iam.create_role(RoleName=kb_role_name, AssumeRolePolicyDocument=_BEDROCK_TRUST)

    def _cleanup_kb_role():
        try:
            iam.delete_role_policy(RoleName=kb_role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=kb_role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_kb_role)
    iam.put_role_policy(
        RoleName=kb_role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.titan-embed-text-v1",
                    },
                    {
                        "Effect": "Allow",
                        "Action": "aoss:APIAccessAll",
                        "Resource": collection_arn,
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    },
                ],
            }
        ),
    )

    kb_deadline = time.monotonic() + 120
    kb_id = None
    last_err: Any = None
    while time.monotonic() < kb_deadline:
        try:
            kb_resp = bedrock_agent.create_knowledge_base(
                name=name,
                roleArn=kb_role_arn,
                knowledgeBaseConfiguration={
                    "type": "VECTOR",
                    "vectorKnowledgeBaseConfiguration": {
                        "embeddingModelArn": f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.titan-embed-text-v1",
                    },
                },
                storageConfiguration={
                    "type": "OPENSEARCH_SERVERLESS",
                    "opensearchServerlessConfiguration": {
                        "collectionArn": collection_arn,
                        "fieldMapping": {
                            "metadataField": "metadata",
                            "textField": "text",
                            "vectorField": "vector",
                        },
                        "vectorIndexName": index_name,
                    },
                },
                tags={"sim2real": CHECK},
            )
            kb_id = kb_resp["knowledgeBase"]["knowledgeBaseId"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(5)
    if not kb_id:
        raise AssertionError(f"CreateKnowledgeBase never succeeded: {last_err}")
    ctx.on_cleanup(lambda: bedrock_agent.delete_knowledge_base(knowledgeBaseId=kb_id))

    deadline = time.monotonic() + 120
    kb_status = None
    while time.monotonic() < deadline:
        kb_status = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)[
            "knowledgeBase"
        ]["status"]
        if kb_status == "ACTIVE":
            break
        time.sleep(5)
    if kb_status != "ACTIVE":
        raise AssertionError(
            f"knowledge base never became ACTIVE, last status={kb_status}"
        )

    ds_resp = bedrock_agent.create_data_source(
        knowledgeBaseId=kb_id,
        name=f"{name}-ds",
        dataSourceConfiguration={
            "type": "S3",
            "s3Configuration": {"bucketArn": bucket_arn},
        },
    )
    ds_id = ds_resp["dataSource"]["dataSourceId"]
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_data_source(
            knowledgeBaseId=kb_id, dataSourceId=ds_id
        )
    )

    job_resp = bedrock_agent.start_ingestion_job(
        knowledgeBaseId=kb_id, dataSourceId=ds_id
    )
    job_id = job_resp["ingestionJob"]["ingestionJobId"]
    deadline = time.monotonic() + 300
    job_status = None
    while time.monotonic() < deadline:
        job_status = bedrock_agent.get_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )["ingestionJob"]["status"]
        if job_status == "COMPLETE":
            break
        if job_status == "FAILED":
            raise AssertionError("ingestion job failed")
        time.sleep(2)
    if job_status != "COMPLETE":
        raise AssertionError(f"ingestion job never completed, last status={job_status}")

    return kb_id


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
