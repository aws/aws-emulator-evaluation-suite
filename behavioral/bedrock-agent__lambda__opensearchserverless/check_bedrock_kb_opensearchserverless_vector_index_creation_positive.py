"""bedrock-kb-opensearchserverless-vector-index-creation-positive."""

from __future__ import annotations

import json
import time
import urllib.parse
from typing import Any

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bedrock-kb-opensearchserverless-vector-index-creation-positive"
GROUP = "arn-resolution"
SERVICES = ["bedrock-agent", "lambda", "opensearchserverless"]

VECTOR_FIELD = "vec"
TEXT_FIELD = "chunk_text"
METADATA_FIELD = "chunk_meta"
EMBED_DIMS = 1536


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """The vectorIndexName and fieldMapping supplied to CreateKnowledgeBase must match
    the fields of an already-existing OpenSearch Serverless index; when they do, a
    real ingestion job against that index runs to completion (not just KB creation)."""
    coll_name = _aoss_name(ctx, "sim2real-idxk")
    role_name = ctx.unique_name("sim2real-kb-role-")
    role_arn = _create_kb_role(ctx, role_name)
    _create_encryption_policy(ctx, coll_name)
    _create_network_policy(ctx, coll_name)
    _create_data_access_policy(ctx, coll_name, [role_arn, _caller_arn(ctx)])

    coll = _create_vectorsearch_collection(ctx, coll_name)
    detail = _wait_collection_active(ctx, coll["id"])
    collection_arn = detail["arn"]
    endpoint = detail["collectionEndpoint"]

    index_name = _aoss_name(ctx, "sim2real-vix")
    field_mapping = {
        "vectorField": VECTOR_FIELD,
        "textField": TEXT_FIELD,
        "metadataField": METADATA_FIELD,
    }
    search_client = _make_search_client(ctx, endpoint)
    _create_vector_index(ctx, search_client, index_name, field_mapping)

    kb_name = ctx.unique_name("sim2real-kb-")
    kb = _create_knowledge_base(
        ctx, kb_name, role_arn, collection_arn, index_name, field_mapping
    )
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(
        lambda: ctx.client("bedrock-agent").delete_knowledge_base(knowledgeBaseId=kb_id)
    )
    _wait_kb_status(ctx, kb_id, {"ACTIVE", "FAILED"})

    bucket, key, _ = _create_s3_source_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    ds = _create_s3_data_source(ctx, kb_id, bucket_arn, ctx.unique_name("sim2real-ds-"))
    ds_id = ds["dataSourceId"]
    ctx.on_cleanup(
        lambda: ctx.client("bedrock-agent").delete_data_source(
            knowledgeBaseId=kb_id, dataSourceId=ds_id
        )
    )

    job = _start_ingestion_and_wait(ctx, kb_id, ds_id)
    assert job["status"] == "COMPLETE", (
        f"ingestion job did not complete against the matching index: {job}"
    )
    stats = job.get("statistics", {})
    assert stats.get("numberOfDocumentsScanned", 0) >= 1, (
        f"expected at least one scanned document: {stats}"
    )
    assert stats.get("numberOfNewDocumentsIndexed", 0) >= 1, (
        f"expected at least one indexed document: {stats}"
    )



def _aoss_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix).lower()
    raw = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw)
    return raw[:32].rstrip("-")


def _caller_arn(ctx: Any) -> str:
    return ctx.client("sts").get_caller_identity()["Arn"]


def _create_kb_role(ctx: Any, name: str) -> str:
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["bedrock:InvokeModel"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["aoss:APIAccessAll"], "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=name,
        PolicyName="sim2real-inline",
        PolicyDocument=json.dumps(policy_doc),
    )
    return role["Arn"]


def _delete_role(ctx: Any, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_encryption_policy(ctx: Any, coll_name: str) -> None:
    client = ctx.client("opensearchserverless")
    name = _aoss_name(ctx, "sim2real-enc")
    policy = json.dumps(
        {
            "Rules": [
                {"ResourceType": "collection", "Resource": [f"collection/{coll_name}"]}
            ],
            "AWSOwnedKey": True,
        }
    )
    client.create_security_policy(name=name, type="encryption", policy=policy)
    ctx.on_cleanup(lambda: _delete_security_policy(ctx, name, "encryption"))


def _create_network_policy(ctx: Any, coll_name: str) -> None:
    client = ctx.client("opensearchserverless")
    name = _aoss_name(ctx, "sim2real-net")
    policy = json.dumps(
        [
            {
                "Description": "public access for sim2real test collection",
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": [f"collection/{coll_name}"],
                    },
                    {
                        "ResourceType": "dashboard",
                        "Resource": [f"collection/{coll_name}"],
                    },
                ],
                "AllowFromPublic": True,
            }
        ]
    )
    client.create_security_policy(name=name, type="network", policy=policy)
    ctx.on_cleanup(lambda: _delete_security_policy(ctx, name, "network"))


def _delete_security_policy(ctx: Any, name: str, type_: str) -> None:
    try:
        ctx.client("opensearchserverless").delete_security_policy(name=name, type=type_)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_data_access_policy(
    ctx: Any, coll_name: str, principal_arns: list[str]
) -> None:
    client = ctx.client("opensearchserverless")
    name = _aoss_name(ctx, "sim2real-dap")
    policy = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "index",
                        "Resource": [f"index/{coll_name}/*"],
                        "Permission": [
                            "aoss:CreateIndex",
                            "aoss:DescribeIndex",
                            "aoss:UpdateIndex",
                            "aoss:DeleteIndex",
                            "aoss:ReadDocument",
                            "aoss:WriteDocument",
                        ],
                    },
                    {
                        "ResourceType": "collection",
                        "Resource": [f"collection/{coll_name}"],
                        "Permission": [
                            "aoss:CreateCollectionItems",
                            "aoss:DescribeCollectionItems",
                            "aoss:UpdateCollectionItems",
                        ],
                    },
                ],
                "Principal": principal_arns,
            }
        ]
    )
    client.create_access_policy(name=name, type="data", policy=policy)
    ctx.on_cleanup(lambda: _delete_access_policy(ctx, name))


def _delete_access_policy(ctx: Any, name: str) -> None:
    try:
        ctx.client("opensearchserverless").delete_access_policy(name=name, type="data")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_vectorsearch_collection(ctx: Any, name: str) -> dict[str, str]:
    client = ctx.client("opensearchserverless")
    resp = client.create_collection(name=name, type="VECTORSEARCH")
    coll_id = resp["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _delete_collection(ctx, coll_id))
    return {"id": coll_id}


def _delete_collection(ctx: Any, coll_id: str) -> None:
    try:
        ctx.client("opensearchserverless").delete_collection(id=coll_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_collection_active(
    ctx: Any, coll_id: str, timeout_s: float = 600.0
) -> dict[str, Any]:
    client = ctx.client("opensearchserverless")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        detail = client.batch_get_collection(ids=[coll_id])["collectionDetails"][0]
        if detail["status"] == "ACTIVE":
            return detail
        if detail["status"] == "FAILED":
            raise AssertionError(f"collection creation failed: {detail}")
        time.sleep(2)
    raise AssertionError("collection never became ACTIVE within timeout")


def _make_search_client(ctx: Any, endpoint: str, timeout: int = 30):
    try:
        from opensearchpy import OpenSearch, RequestsHttpConnection
    except ImportError as exc:
        raise AssertionError(
            f"opensearch-py is not installed, cannot do a native data-plane round trip: {exc}"
        )
    # Sign the data-plane calls with the credentials of a ctx-built client, so they run as
    # the same identity the collection's data access policy grants.
    credentials = ctx.client("opensearchserverless")._request_signer._credentials
    try:
        from opensearchpy import AWSV4SignerAuth

        auth = AWSV4SignerAuth(credentials, ctx.region, "aoss")
    except ImportError:
        try:
            from requests_aws4auth import AWS4Auth

            frozen = credentials.get_frozen_credentials()
            auth = AWS4Auth(
                frozen.access_key,
                frozen.secret_key,
                ctx.region,
                "aoss",
                session_token=frozen.token,
            )
        except ImportError as exc:
            raise AssertionError(f"no SigV4 signer available for opensearch-py: {exc}")
    # The collection endpoint the target published, dialed at its own scheme, host and port.
    target = urllib.parse.urlsplit(ctx.endpoint_url(endpoint))
    secure = target.scheme == "https"
    verify = ctx.http_verify
    return OpenSearch(
        hosts=[{"host": target.hostname, "port": target.port or (443 if secure else 80)}],
        http_auth=auth,
        use_ssl=secure,
        verify_certs=verify is not False,
        **({"ca_certs": verify} if isinstance(verify, str) else {}),
        connection_class=RequestsHttpConnection,
        timeout=timeout,
        max_retries=0,
        retry_on_timeout=False,
    )


def _create_vector_index(
    ctx: Any,
    search_client: Any,
    index_name: str,
    field_mapping: dict[str, str],
    dims: int = EMBED_DIMS,
) -> None:
    body = {
        "settings": {"index.knn": True},
        "mappings": {
            "properties": {
                field_mapping["vectorField"]: {
                    "type": "knn_vector",
                    "dimension": dims,
                    "method": {"name": "hnsw", "engine": "faiss", "space_type": "l2"},
                },
                field_mapping["textField"]: {"type": "text"},
                field_mapping["metadataField"]: {"type": "text"},
            }
        },
    }
    last_exc: Exception | None = None
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else max(1.0, min(120.0, left - 5.0)))
    while True:
        try:
            search_client.indices.create(index=index_name, body=body)
            return
        except Exception as exc:  # noqa: BLE001 - data access rule propagation is eventually consistent
            last_exc = exc
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    raise AssertionError(f"could not create vector index after retries: {last_exc}")


def _create_knowledge_base(
    ctx: Any,
    name: str,
    role_arn: str,
    collection_arn: str,
    index_name: str,
    field_mapping: dict[str, str],
    timeout_s: float = 180.0,
) -> dict[str, Any]:
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = bedrock_agent.create_knowledge_base(
                name=name,
                roleArn=role_arn,
                knowledgeBaseConfiguration={
                    "type": "VECTOR",
                    "vectorKnowledgeBaseConfiguration": {
                        "embeddingModelArn": f"arn:aws:bedrock:{ctx.region}::foundation-model/amazon.titan-embed-text-v1"
                    },
                },
                storageConfiguration={
                    "type": "OPENSEARCH_SERVERLESS",
                    "opensearchServerlessConfiguration": {
                        "collectionArn": collection_arn,
                        "vectorIndexName": index_name,
                        "fieldMapping": field_mapping,
                    },
                },
            )
            return resp["knowledgeBase"]
        except botocore.exceptions.ClientError as exc:
            last_err = exc
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            # A just-created index reaches the knowledge base's view of the collection late.
            if code == "ValidationException" and (
                "assume" in msg or "role" in msg or "no such index" in msg
            ):
                time.sleep(2)
                continue
            raise
    raise last_err  # type: ignore[misc]


def _wait_kb_status(
    ctx: Any, kb_id: str, target_statuses: set[str], timeout_s: float = 180.0
) -> dict[str, Any]:
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        kb = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
        if kb["status"] in target_statuses:
            return kb
        time.sleep(5)
    raise AssertionError(f"knowledge base never reached {target_statuses}")


def _create_s3_source_bucket(ctx: Any, key: str = "doc.txt") -> tuple[str, str, str]:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-kb-src-")
    body = "Amazon Bedrock Knowledge Bases can use Amazon OpenSearch Serverless as a vector store for retrieval augmented generation."
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode())
    return bucket, key, body


def _empty_and_delete_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_s3_data_source(
    ctx: Any, kb_id: str, bucket_arn: str, name: str
) -> dict[str, Any]:
    bedrock_agent = ctx.client("bedrock-agent")
    resp = bedrock_agent.create_data_source(
        knowledgeBaseId=kb_id,
        name=name,
        dataSourceConfiguration={
            "type": "S3",
            "s3Configuration": {"bucketArn": bucket_arn},
        },
    )
    return resp["dataSource"]


def _start_ingestion_and_wait(
    ctx: Any, kb_id: str, ds_id: str, timeout_s: float = 600.0
) -> dict[str, Any]:
    bedrock_agent = ctx.client("bedrock-agent")
    job = bedrock_agent.start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id)[
        "ingestionJob"
    ]
    job_id = job["ingestionJobId"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        job = bedrock_agent.get_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )["ingestionJob"]
        if job["status"] in ("COMPLETE", "FAILED"):
            return job
        time.sleep(2)
    raise AssertionError("ingestion job never reached a terminal state")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
