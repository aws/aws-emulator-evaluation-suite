"""get-document-content-nonexistent-document-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-document-content-nonexistent-document-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent-runtime"]

_DOC_TEXT = "The sim2real test document for GetDocumentContent says the password is CANTALOUPE."


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """GetDocumentContent returns the ingested text of a managed knowledge base's document, and answers
    ResourceNotFoundException for a never-ingested documentId and for a never-created knowledge base
    ("Knowledge Base with id S2RFAKEKB0 does not exist")."""
    runtime = ctx.client("bedrock-agent-runtime")

    kb_role_arn = _create_kb_role(ctx)
    kb_id = _create_managed_knowledge_base(ctx, kb_role_arn)
    ds_id = _create_custom_data_source(ctx, kb_id)
    document_id = ctx.unique_name("sim2real-doc-")
    _ingest_document(ctx, kb_id, ds_id, document_id, _DOC_TEXT)

    # Positive control: the real, ingested document is retrievable through GetDocumentContent.
    # Without this, a target that unconditionally raises ResourceNotFoundException for
    # GetDocumentContent -- never having implemented it at all -- would score identically to a
    # correct one on the not-found assertions below.
    resp = runtime.get_document_content(
        knowledgeBaseId=kb_id, dataSourceId=ds_id, documentId=document_id
    )
    assert resp["mimeType"], f"expected a non-empty mimeType, got {resp['mimeType']!r}"
    downloaded = _download(ctx, resp["presignedUrl"])
    assert _DOC_TEXT.encode("utf-8") in downloaded, f"presigned content mismatch: got {downloaded!r}"

    # Same real knowledge base, same real data source -- only the documentId was never
    # ingested. This isolates the not-found semantics to the document lookup itself.
    never_ingested_id = ctx.unique_name("sim2real-doc-never-ingested-")
    # message varies: AWS appends a per-request id and an SDK attempt count to the text.
    code, _ = _error(
        lambda: runtime.get_document_content(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, documentId=never_ingested_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-ingested document in a REAL "
        f"knowledge base/data source, got {code!r}"
    )

    # Fully well-formed but never-created triple.
    code, message = _error(
        lambda: runtime.get_document_content(
            knowledgeBaseId="S2RFAKEKB0",
            dataSourceId="S2RFAKEDS",
            documentId="sim2real-fake-document",
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a fully fabricated triple, got {code!r}"
    )
    assert message == "Knowledge Base with id S2RFAKEKB0 does not exist", (
        f"expected message 'Knowledge Base with id S2RFAKEKB0 does not exist', got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _download(ctx, url: str) -> bytes:
    import urllib.request

    url, headers = ctx.endpoint_route(url)
    with urllib.request.urlopen(  # noqa: S310 - presigned https URL
        urllib.request.Request(url, headers=headers),
        timeout=30,
        context=_ssl_context(ctx.http_verify),
    ) as resp:
        return resp.read()


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _create_kb_role(ctx) -> str:
    # A managed knowledge base with the default MANAGED embedding model and a CUSTOM connector
    # data source needs no inline permissions at all -- Bedrock owns embedding, storage and
    # indexing, and direct document ingestion never touches another AWS resource.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-kbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    try:
        ctx.client("iam").delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_managed_knowledge_base(ctx, kb_role_arn: str) -> str:
    ba = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-kb-")
    last_exc = None
    kb_id = None
    for _ in range(10):
        try:
            kb_id = ba.create_knowledge_base(
                name=name,
                roleArn=kb_role_arn,
                knowledgeBaseConfiguration={
                    "type": "MANAGED",
                    "managedKnowledgeBaseConfiguration": {"embeddingModelType": "MANAGED"},
                },
            )["knowledgeBase"]["knowledgeBaseId"]
            break
        except ba.exceptions.ValidationException as exc:
            last_exc = exc
            time.sleep(5)  # IAM role propagation before Bedrock can assume it
    if kb_id is None:
        raise AssertionError(f"could not create knowledge base after role propagation wait: {last_exc}")
    ctx.on_cleanup(lambda: _delete_knowledge_base(ctx, kb_id))
    status = _poll_until(
        lambda: ba.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120,
        description="knowledge base ACTIVE",
    )
    if status != "ACTIVE":
        raise AssertionError(f"knowledge base failed to become active: {status}")
    return kb_id


def _delete_knowledge_base(ctx, kb_id: str) -> None:
    try:
        ctx.client("bedrock-agent").delete_knowledge_base(knowledgeBaseId=kb_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_custom_data_source(ctx, kb_id: str) -> str:
    ba = ctx.client("bedrock-agent")
    ds_name = ctx.unique_name("sim2real-ds-")
    ds_id = ba.create_data_source(
        knowledgeBaseId=kb_id,
        name=ds_name,
        dataSourceConfiguration={
            "type": "MANAGED_KNOWLEDGE_BASE_CONNECTOR",
            "managedKnowledgeBaseConnectorConfiguration": {
                "connectorParameters": {"type": "CUSTOM", "version": "1", "aclEnabled": False}
            },
        },
    )["dataSource"]["dataSourceId"]
    ctx.on_cleanup(lambda: _delete_data_source(ctx, kb_id, ds_id))
    status = _poll_until(
        lambda: ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=60,
        description="data source AVAILABLE",
    )
    if status != "AVAILABLE":
        raise AssertionError(f"data source failed to become available: {status}")
    return ds_id


def _delete_data_source(ctx, kb_id: str, ds_id: str) -> None:
    try:
        ctx.client("bedrock-agent").delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _ingest_document(ctx, kb_id: str, ds_id: str, document_id: str, text: str) -> None:
    ba = ctx.client("bedrock-agent")
    ba.ingest_knowledge_base_documents(
        knowledgeBaseId=kb_id,
        dataSourceId=ds_id,
        documents=[
            {
                "content": {
                    "dataSourceType": "CUSTOM",
                    "custom": {
                        "customDocumentIdentifier": {"id": document_id},
                        "inlineContent": {"textContent": {"data": text}, "type": "TEXT"},
                        "sourceType": "IN_LINE",
                    },
                }
            }
        ],
    )

    def _probe():
        details = ba.get_knowledge_base_documents(
            knowledgeBaseId=kb_id,
            dataSourceId=ds_id,
            documentIdentifiers=[{"dataSourceType": "CUSTOM", "custom": {"id": document_id}}],
        )["documentDetails"]
        return details[0]["status"] if details else "NOT_FOUND"

    status = _poll_until(
        _probe,
        lambda s: s in ("INDEXED", "FAILED", "IGNORED"),
        timeout_s=120,
        description="document INDEXED",
    )
    if status != "INDEXED":
        raise AssertionError(f"direct document ingestion did not INDEX the document: {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
