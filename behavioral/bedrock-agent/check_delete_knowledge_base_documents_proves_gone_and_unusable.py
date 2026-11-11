"""delete-knowledge-base-documents-proves-gone-and-unusable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-knowledge-base-documents-proves-gone-and-unusable"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent"]

_EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
_EMBEDDING_DIMENSION = 1024


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteKnowledgeBaseDocuments removes exactly the named document: it stops being listed
    and stops being INDEXED, while its twin -- ingested identically in the same run -- is
    untouched, and a repeat delete is idempotent."""
    bedrock = ctx.client("bedrock-agent")
    account_id, partition = _caller_identity(ctx)
    kb_id = _create_s3_vectors_kb(ctx, account_id, partition)
    ds_id = _create_custom_data_source(ctx, kb_id)

    # Two documents, ingested identically. One is the subject of the delete; the other is the
    # control that proves the delete was scoped rather than a wipe.
    doomed_id = ctx.unique_name("s2rkbdoc-doomed-")
    survivor_id = ctx.unique_name("s2rkbdoc-survivor-")
    _ingest_document(ctx, kb_id, ds_id, doomed_id, "the document this check will delete")
    _ingest_document(ctx, kb_id, ds_id, survivor_id, "the document that must survive the delete")

    for doc_id in (doomed_id, survivor_id):
        detail = _poll_document(
            ctx, kb_id, ds_id, doc_id, 240.0, "a custom in-line document must reach INDEXED"
        )
        assert detail["status"] == "INDEXED", (
            f"document {doc_id} must be INDEXED before the delete is meaningful, got "
            f"{detail['status']!r}: {detail.get('statusReason')}"
        )

    listed_before = _listed_identifiers(ctx, kb_id, ds_id)
    assert listed_before == {doomed_id, survivor_id}, (
        f"ListKnowledgeBaseDocuments must report exactly the two documents this check ingested: "
        f"expected {sorted([doomed_id, survivor_id])}, got {sorted(listed_before)}"
    )

    # ---- the delete -------------------------------------------------------------
    bedrock.delete_knowledge_base_documents(
        knowledgeBaseId=kb_id,
        dataSourceId=ds_id,
        documentIdentifiers=[_identifier(doomed_id)],
    )

    # ---- an independent read, via a DIFFERENT operation, shows it gone -----------
    # ListKnowledgeBaseDocuments is not the operation that deleted, and it reads the collection
    # rather than echoing the delete's own response.
    deadline = time.monotonic() + 180.0
    listed_after = None
    while time.monotonic() < deadline:
        listed_after = _listed_identifiers(ctx, kb_id, ds_id)
        if doomed_id not in listed_after:
            break
        time.sleep(5)
    else:
        raise AssertionError(
            f"document {doomed_id} was still listed 180s after DeleteKnowledgeBaseDocuments; "
            f"ListKnowledgeBaseDocuments returned {sorted(listed_after or set())}"
        )

    # ---- the delete is scoped: the twin is untouched ------------------------------------
    assert listed_after == {survivor_id}, (
        f"the delete must remove ONLY the document it named: expected the listing to be exactly "
        f"[{survivor_id}], got {sorted(listed_after)}"
    )
    survivor_detail = _document_detail(ctx, kb_id, ds_id, survivor_id)
    assert survivor_detail is not None, (
        f"the surviving document {survivor_id} must still be retrievable by identifier after its "
        f"twin was deleted, but GetKnowledgeBaseDocuments returned nothing for it"
    )
    assert survivor_detail["status"] == "INDEXED", (
        f"the surviving document {survivor_id} must still be INDEXED after its twin was deleted, "
        f"got {survivor_detail['status']!r}"
    )

    # ---- the deleted document is no longer INDEXED by a targeted read -----------------------
    doomed_detail = _document_detail(ctx, kb_id, ds_id, doomed_id)
    if doomed_detail is None:
        terminal = "absent-from-GetKnowledgeBaseDocuments"
    else:
        terminal = doomed_detail["status"]
        assert terminal != "INDEXED", (
            f"document {doomed_id} was deleted but GetKnowledgeBaseDocuments still reports it as "
            f"INDEXED -- the delete did not take effect at the destination: {doomed_detail}"
        )
    assert terminal in (
        "absent-from-GetKnowledgeBaseDocuments",
        "DELETING",
        "NOT_FOUND",
        "DELETE_IN_PROGRESS",
    ), (
        f"a deleted document must be absent or in a delete-ish state; document {doomed_id} "
        f"reports {terminal!r}, which is neither."
    )

    # ---- a repeat delete of the dead identifier is idempotent --------------------
    # Real AWS accepts the repeat delete; any ClientError here fails the check.
    bedrock.delete_knowledge_base_documents(
        knowledgeBaseId=kb_id,
        dataSourceId=ds_id,
        documentIdentifiers=[_identifier(doomed_id)],
    )
    still_gone = _listed_identifiers(ctx, kb_id, ds_id)
    assert still_gone == {survivor_id}, (
        f"a repeat delete must not disturb the surviving document: expected [{survivor_id}], got "
        f"{sorted(still_gone)}"
    )

    # ---- the identifier is REUSABLE. Re-ingesting the same id must work, which
    # proves the delete freed the identifier rather than tombstoning it.
    _ingest_document(ctx, kb_id, ds_id, doomed_id, "the identifier is reusable after deletion")
    reborn = _poll_document(
        ctx, kb_id, ds_id, doomed_id, 240.0, "a deleted document identifier must be reusable"
    )
    assert reborn["status"] == "INDEXED", (
        f"re-ingesting the deleted identifier {doomed_id} must reach INDEXED, proving the "
        f"identifier was freed; got {reborn['status']!r}: {reborn.get('statusReason')}"
    )
    listed_final = _listed_identifiers(ctx, kb_id, ds_id)
    assert listed_final == {doomed_id, survivor_id}, (
        f"after re-ingestion both documents must be listed again: expected "
        f"{sorted([doomed_id, survivor_id])}, got {sorted(listed_final)}"
    )


import json  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402


def _identifier(doc_id: str) -> dict:
    return {"dataSourceType": "CUSTOM", "custom": {"id": doc_id}}


def _swallow_not_found(fn) -> None:
    """Cleanup helper: a resource already gone is not a teardown failure, anything else is."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _caller_identity(ctx) -> tuple[str, str]:
    identity = ctx.client("sts").get_caller_identity()
    return identity["Account"], identity["Arn"].split(":")[1]


def _ingest_document(ctx, kb_id: str, ds_id: str, doc_id: str, body: str) -> None:
    resp = ctx.client("bedrock-agent").ingest_knowledge_base_documents(
        knowledgeBaseId=kb_id,
        dataSourceId=ds_id,
        documents=[
            {
                "content": {
                    "dataSourceType": "CUSTOM",
                    "custom": {
                        "customDocumentIdentifier": {"id": doc_id},
                        "sourceType": "IN_LINE",
                        "inlineContent": {
                            "type": "BYTE",
                            "byteContent": {
                                "mimeType": "text/plain",
                                "data": (
                                    f"{body}. This paragraph exists so the ingestion pipeline "
                                    f"has real text to chunk and embed for document {doc_id}."
                                ).encode(),
                            },
                        },
                    },
                }
            }
        ],
    )
    accepted = resp["documentDetails"][0]["identifier"]["custom"]["id"]
    assert accepted == doc_id, (
        f"IngestKnowledgeBaseDocuments must echo the identifier it was given: expected "
        f"{doc_id!r}, got {accepted!r}"
    )


def _document_detail(ctx, kb_id: str, ds_id: str, doc_id: str):
    """Targeted read for one document, or None when the service reports nothing for it."""
    details = ctx.client("bedrock-agent").get_knowledge_base_documents(
        knowledgeBaseId=kb_id,
        dataSourceId=ds_id,
        documentIdentifiers=[_identifier(doc_id)],
    )["documentDetails"]
    for detail in details:
        if detail["identifier"].get("custom", {}).get("id") == doc_id:
            return detail
    return None


def _poll_document(ctx, kb_id: str, ds_id: str, doc_id: str, timeout_s: float, reason: str) -> dict:
    """Bounded poll until a document reaches a terminal state. RAISES on timeout and on FAILED."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _document_detail(ctx, kb_id, ds_id, doc_id)
        if last is not None:
            if last["status"] == "FAILED":
                raise AssertionError(
                    f"document {doc_id} reached FAILED while waiting ({reason}): "
                    f"{last.get('statusReason')}"
                )
            if last["status"] in ("INDEXED", "IGNORED"):
                return last
        time.sleep(5)
    raise AssertionError(
        f"document {doc_id} never reached a terminal indexing state within {timeout_s}s "
        f"({reason}); last detail={last}"
    )


def _listed_identifiers(ctx, kb_id: str, ds_id: str) -> set:
    """Custom document ids currently listed against the data source (paginated)."""
    bedrock = ctx.client("bedrock-agent")
    found = set()
    token = None
    while True:
        kwargs = {"knowledgeBaseId": kb_id, "dataSourceId": ds_id, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = bedrock.list_knowledge_base_documents(**kwargs)
        for detail in resp["documentDetails"]:
            custom_id = detail["identifier"].get("custom", {}).get("id")
            if custom_id is not None:
                found.add(custom_id)
        token = resp.get("nextToken")
        if not token:
            return found


def _create_s3_vectors_kb(ctx, account_id: str, partition: str) -> str:
    """S3 Vectors rather than OpenSearch Serverless: an OSS collection needs minutes to reach
    ACTIVE, which this check's budget cannot absorb."""
    s3vectors = ctx.client("s3vectors")
    bedrock = ctx.client("bedrock-agent")

    vector_bucket = ctx.unique_name("sim2real-kbdocdel-vec-").lower()
    index_name = ctx.unique_name("sim2real-kbdocdel-idx-").lower()
    s3vectors.create_vector_bucket(vectorBucketName=vector_bucket)
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: s3vectors.delete_vector_bucket(vectorBucketName=vector_bucket)
        )
    )
    s3vectors.create_index(
        vectorBucketName=vector_bucket,
        indexName=index_name,
        dataType="float32",
        dimension=_EMBEDDING_DIMENSION,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: s3vectors.delete_index(vectorBucketName=vector_bucket, indexName=index_name)
        )
    )

    vector_bucket_arn = (
        f"arn:{partition}:s3vectors:{ctx.region}:{account_id}:bucket/{vector_bucket}"
    )
    index_arn = f"{vector_bucket_arn}/index/{index_name}"
    embedding_model_arn = (
        f"arn:{partition}:bedrock:{ctx.region}::foundation-model/{_EMBEDDING_MODEL}"
    )
    role_arn = _create_kb_role(
        ctx, account_id, partition, vector_bucket_arn, index_arn, embedding_model_arn
    )

    kb_id = _create_kb_with_propagation_retry(
        ctx,
        name=ctx.unique_name("sim2real-kbdocdel-kb-"),
        roleArn=role_arn,
        knowledgeBaseConfiguration={
            "type": "VECTOR",
            "vectorKnowledgeBaseConfiguration": {"embeddingModelArn": embedding_model_arn},
        },
        storageConfiguration={
            "type": "S3_VECTORS",
            "s3VectorsConfiguration": {
                "vectorBucketArn": vector_bucket_arn,
                "indexArn": index_arn,
            },
        },
        tags={"sim2real-check": CHECK},
    )

    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        last = bedrock.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"]
        if last == "FAILED":
            raise AssertionError(f"knowledge base {kb_id} reached FAILED instead of ACTIVE")
        if last == "ACTIVE":
            return kb_id
        time.sleep(5)
    raise AssertionError(
        f"knowledge base {kb_id} never reached ACTIVE within 180s; last status={last!r}"
    )


def _create_kb_role(
    ctx, account_id, partition, vector_bucket_arn, index_arn, embedding_model_arn
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-kbdocdel-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": (
                            f"arn:{partition}:bedrock:{ctx.region}:{account_id}:knowledge-base/*"
                        )
                    },
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow_not_found(lambda: iam.delete_role(RoleName=role_name)))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="kb-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": embedding_model_arn,
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
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="kb-access")
        )
    )
    return role_arn


def _create_kb_with_propagation_retry(ctx, timeout_s: float = 120.0, **kwargs) -> str:
    bedrock = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            kb_id = bedrock.create_knowledge_base(**kwargs)["knowledgeBase"]["knowledgeBaseId"]
            ctx.on_cleanup(
                lambda: _swallow_not_found(
                    lambda: bedrock.delete_knowledge_base(knowledgeBaseId=kb_id)
                )
            )
            return kb_id
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            last_exc = exc
            time.sleep(5)  # bounded: inside a deadline-guarded IAM-propagation retry
    raise AssertionError(
        f"CreateKnowledgeBase never succeeded within {timeout_s}s of role-propagation retries; "
        f"last error={last_exc}"
    )


def _create_custom_data_source(ctx, kb_id: str) -> str:
    bedrock = ctx.client("bedrock-agent")
    ds_id = bedrock.create_data_source(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-kbdocdel-ds-"),
        dataSourceConfiguration={"type": "CUSTOM"},
        dataDeletionPolicy="RETAIN",
    )["dataSource"]["dataSourceId"]
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: bedrock.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)
        )
    )
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        last = bedrock.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"][
            "status"
        ]
        if last == "FAILED":
            raise AssertionError(f"data source {ds_id} reached FAILED instead of AVAILABLE")
        if last == "AVAILABLE":
            return ds_id
        time.sleep(5)
    raise AssertionError(
        f"data source {ds_id} never reached AVAILABLE within 120s; last status={last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
