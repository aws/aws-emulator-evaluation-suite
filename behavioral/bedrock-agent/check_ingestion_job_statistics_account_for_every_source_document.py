"""ingestion-job-statistics-account-for-every-source-document."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ingestion-job-statistics-account-for-every-source-document"
GROUP = "state-machine"
SERVICES = ["bedrock-agent"]

_EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
_EMBEDDING_DIMENSION = 1024

# The number of source documents is chosen HERE, so the expected statistics are derived from
# this run rather than recorded. Changing this constant must change every expected count.
_DOCUMENT_COUNT = 4


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Ingestion job statistics account for every source document exactly: the first job
    reports all N as new, a re-run over unchanged bytes reports none as new while still
    scanning N, and changing one document is attributed to exactly one document."""
    s3 = ctx.client("s3")
    account_id, partition = _caller_identity(ctx)
    source_bucket, source_bucket_arn = _create_source_bucket(ctx)

    keys = [f"doc-{i:02d}.txt" for i in range(_DOCUMENT_COUNT)]
    for i, key in enumerate(keys):
        s3.put_object(
            Bucket=source_bucket,
            Key=key,
            Body=_document_body(i, revision=1),
            ContentType="text/plain",
        )

    # An independent read at S3 confirming the source really is N objects, so a later count
    # mismatch cannot be blamed on a failed upload.
    listed = s3.list_objects_v2(Bucket=source_bucket)
    uploaded = sorted(obj["Key"] for obj in listed.get("Contents", []))
    assert uploaded == sorted(keys), (
        f"the source prefix must hold exactly the {_DOCUMENT_COUNT} documents this check "
        f"uploaded: expected {sorted(keys)}, got {uploaded}"
    )

    kb_id = _create_s3_vectors_kb(ctx, account_id, partition, source_bucket_arn)
    ds_id = _create_data_source(ctx, kb_id, source_bucket_arn)

    # ---- Job 1: every document is new ----------------------------------------------------
    stats_1 = _run_ingestion_job(ctx, kb_id, ds_id, leg="first ingestion of N new documents")
    _assert_accounting_identity(stats_1, leg="job 1")
    assert stats_1["numberOfDocumentsScanned"] == _DOCUMENT_COUNT, (
        f"job 1 numberOfDocumentsScanned: expected {_DOCUMENT_COUNT} (the documents this check "
        f"uploaded), got {stats_1['numberOfDocumentsScanned']}"
    )
    assert stats_1["numberOfNewDocumentsIndexed"] == _DOCUMENT_COUNT, (
        f"job 1 numberOfNewDocumentsIndexed: every document is new on the first ingestion, so "
        f"expected {_DOCUMENT_COUNT}, got {stats_1['numberOfNewDocumentsIndexed']}"
    )
    assert stats_1["numberOfDocumentsFailed"] == 0, (
        f"job 1 numberOfDocumentsFailed: expected 0 for {_DOCUMENT_COUNT} well-formed plain-text "
        f"documents, got {stats_1['numberOfDocumentsFailed']}"
    )
    assert stats_1["numberOfModifiedDocumentsIndexed"] == 0, (
        f"job 1 numberOfModifiedDocumentsIndexed: nothing pre-existed, so expected 0, got "
        f"{stats_1['numberOfModifiedDocumentsIndexed']}"
    )
    assert stats_1["numberOfDocumentsDeleted"] == 0, (
        f"job 1 numberOfDocumentsDeleted: nothing was removed, so expected 0, got "
        f"{stats_1['numberOfDocumentsDeleted']}"
    )
    assert stats_1.get("numberOfDocumentsSkipped", 0) == 0, (
        f"job 1 numberOfDocumentsSkipped: expected 0 for well-formed documents, got "
        f"{stats_1.get('numberOfDocumentsSkipped')}"
    )

    # Independent read at the destination via a DIFFERENT operation than StartIngestionJob:
    # every uploaded document must be listed against the knowledge base as INDEXED.
    indexed = _document_statuses(ctx, kb_id, ds_id)
    assert len(indexed) == _DOCUMENT_COUNT, (
        f"ListKnowledgeBaseDocuments must report the {_DOCUMENT_COUNT} ingested documents, got "
        f"{len(indexed)}: {indexed}"
    )
    not_indexed = {k: v for k, v in indexed.items() if v != "INDEXED"}
    assert not not_indexed, (
        f"every document must be INDEXED after a COMPLETE job with 0 failures, but these are "
        f"not: {not_indexed}"
    )

    # ---- Job 2: nothing changed, so nothing is new ---------------------------------------
    stats_2 = _run_ingestion_job(ctx, kb_id, ds_id, leg="re-ingestion with unchanged bytes")
    _assert_accounting_identity(stats_2, leg="job 2")
    assert stats_2["numberOfDocumentsScanned"] == _DOCUMENT_COUNT, (
        f"job 2 numberOfDocumentsScanned: unchanged documents are still scanned, so expected "
        f"{_DOCUMENT_COUNT}, got {stats_2['numberOfDocumentsScanned']}"
    )
    assert stats_2["numberOfNewDocumentsIndexed"] == 0, (
        f"job 2 numberOfNewDocumentsIndexed: no source bytes changed between job 1 and job 2, so "
        f"NOTHING is new; expected 0, got {stats_2['numberOfNewDocumentsIndexed']}"
    )
    assert stats_2["numberOfModifiedDocumentsIndexed"] == 0, (
        f"job 2 numberOfModifiedDocumentsIndexed: no source bytes changed, so expected 0, got "
        f"{stats_2['numberOfModifiedDocumentsIndexed']}"
    )
    assert stats_2["numberOfDocumentsDeleted"] == 0, (
        f"job 2 numberOfDocumentsDeleted: no document was removed from the source, so expected "
        f"0, got {stats_2['numberOfDocumentsDeleted']}"
    )
    assert stats_2.get("numberOfDocumentsSkipped", 0) == 0, (
        f"job 2 numberOfDocumentsSkipped: unchanged well-formed documents are not skipped, so "
        f"expected 0, got {stats_2.get('numberOfDocumentsSkipped')}"
    )

    # ---- Job 3: exactly one document changed ---------------------------------------------
    changed_key = keys[0]
    s3.put_object(
        Bucket=source_bucket,
        Key=changed_key,
        Body=_document_body(0, revision=2),
        ContentType="text/plain",
    )
    stats_3 = _run_ingestion_job(ctx, kb_id, ds_id, leg="re-ingestion after one document changed")
    _assert_accounting_identity(stats_3, leg="job 3")
    assert stats_3["numberOfDocumentsScanned"] == _DOCUMENT_COUNT, (
        f"job 3 numberOfDocumentsScanned: the source is still {_DOCUMENT_COUNT} documents, got "
        f"{stats_3['numberOfDocumentsScanned']}"
    )
    # The attribution rule: exactly ONE document was touched, so exactly one is re-indexed, and
    # the other N-1 are not. Asserted as a total over both re-index buckets so the check does
    # not depend on whether AWS calls a re-uploaded key "new" or "modified".
    reindexed = (
        stats_3["numberOfNewDocumentsIndexed"] + stats_3["numberOfModifiedDocumentsIndexed"]
    )
    assert reindexed == 1, (
        f"job 3: exactly one of {_DOCUMENT_COUNT} documents changed, so exactly one may be "
        f"re-indexed; got numberOfNewDocumentsIndexed="
        f"{stats_3['numberOfNewDocumentsIndexed']} + numberOfModifiedDocumentsIndexed="
        f"{stats_3['numberOfModifiedDocumentsIndexed']} = {reindexed}"
    )
    assert stats_3["numberOfDocumentsFailed"] == 0, (
        f"job 3 numberOfDocumentsFailed: expected 0, got {stats_3['numberOfDocumentsFailed']}"
    )
    assert stats_3["numberOfDocumentsDeleted"] == 0, (
        f"job 3 numberOfDocumentsDeleted: no document was removed from the source, so expected "
        f"0, got {stats_3['numberOfDocumentsDeleted']}"
    )
    assert stats_3.get("numberOfDocumentsSkipped", 0) == 0, (
        f"job 3 numberOfDocumentsSkipped: expected 0, the {_DOCUMENT_COUNT - 1} untouched "
        f"documents are unchanged (not skipped) and the one changed document is well-formed, "
        f"got {stats_3.get('numberOfDocumentsSkipped')}"
    )

    # The three jobs must be distinguishable in the job history -- a target that reuses one job
    # record, or reports a constant statistics blob, fails here.
    jobs = _list_ingestion_jobs(ctx, kb_id, ds_id)
    assert len(jobs) == 3, (
        f"ListIngestionJobs must report the three jobs this check started, got {len(jobs)}: "
        f"{[j.get('ingestionJobId') for j in jobs]}"
    )
    new_counts = [stats_1, stats_2, stats_3]
    assert [s["numberOfNewDocumentsIndexed"] for s in new_counts][:2] == [_DOCUMENT_COUNT, 0], (
        "the first two jobs must report DIFFERENT new-document counts "
        f"({_DOCUMENT_COUNT} then 0); a target reporting the same statistics for both has no "
        f"change detection: got {[s['numberOfNewDocumentsIndexed'] for s in new_counts]}"
    )


import json  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402

_STAT_FIELDS = (
    "numberOfDocumentsScanned",
    "numberOfNewDocumentsIndexed",
    "numberOfModifiedDocumentsIndexed",
    "numberOfDocumentsDeleted",
    "numberOfDocumentsFailed",
)


def _document_body(index: int, revision: int) -> bytes:
    """Distinct, embeddable prose per document. Revision 2 differs in bytes from revision 1."""
    return (
        f"Sample document number {index}, revision {revision}. "
        f"This paragraph exists so that the ingestion pipeline has real text to chunk and "
        f"embed. Subject {index}: the behaviour of derived ingestion statistics under "
        f"repeated ingestion of an unchanged set of source documents, revision {revision}."
    ).encode()


def _swallow_not_found(fn) -> None:
    """Cleanup helper: a resource already gone is not a teardown failure, anything else is."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _assert_accounting_identity(stats: dict, leg: str) -> None:
    """new+modified+failed+skipped never exceeds scanned -- a document cannot be actioned twice.

    A scanned but unchanged document is counted in none of the four fields, so scanned bounds
    their sum. numberOfDocumentsSkipped is optional and may be omitted when zero.
    """
    scanned = stats["numberOfDocumentsScanned"]
    accounted = (
        stats["numberOfNewDocumentsIndexed"]
        + stats["numberOfModifiedDocumentsIndexed"]
        + stats["numberOfDocumentsFailed"]
        + stats.get("numberOfDocumentsSkipped", 0)
    )
    assert accounted <= scanned, (
        f"{leg}: new+modified+failed+skipped must never exceed the number of documents scanned "
        f"-- a document cannot be actioned twice. scanned={scanned}, "
        f"new+modified+failed+skipped={accounted}, stats={stats}"
    )


def _caller_identity(ctx) -> tuple[str, str]:
    identity = ctx.client("sts").get_caller_identity()
    return identity["Account"], identity["Arn"].split(":")[1]


def _create_source_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-ingstats-src-").lower()
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the only region where LocationConstraint must be omitted.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        listed = s3.list_objects_v2(Bucket=name)
        for obj in listed.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name, f"arn:aws:s3:::{name}"


def _create_s3_vectors_kb(ctx, account_id: str, partition: str, source_bucket_arn: str) -> str:
    """S3 Vectors rather than OpenSearch Serverless: an OSS collection needs minutes to become
    ACTIVE, which this check's budget cannot absorb on top of three ingestion jobs."""
    s3vectors = ctx.client("s3vectors")
    bedrock = ctx.client("bedrock-agent")

    vector_bucket = ctx.unique_name("sim2real-ingstats-vec-").lower()
    index_name = ctx.unique_name("sim2real-ingstats-idx-").lower()
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
        ctx, account_id, partition, vector_bucket_arn, index_arn, source_bucket_arn,
        embedding_model_arn,
    )

    kb_id = _create_kb_with_propagation_retry(
        ctx,
        name=ctx.unique_name("sim2real-ingstats-kb-"),
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
    ctx, account_id, partition, vector_bucket_arn, index_arn, source_bucket_arn, embedding_model_arn
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ingstats-role-")
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
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [source_bucket_arn, f"{source_bucket_arn}/*"],
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


def _create_data_source(ctx, kb_id: str, source_bucket_arn: str) -> str:
    bedrock = ctx.client("bedrock-agent")
    ds_id = bedrock.create_data_source(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-ingstats-ds-"),
        dataSourceConfiguration={"type": "S3", "s3Configuration": {"bucketArn": source_bucket_arn}},
        # RETAIN so teardown of the data source cannot race the vector-store cleanup and turn a
        # statistics assertion into a teardown flake.
        dataDeletionPolicy="RETAIN",
        vectorIngestionConfiguration={
            "chunkingConfiguration": {
                "chunkingStrategy": "FIXED_SIZE",
                "fixedSizeChunkingConfiguration": {"maxTokens": 300, "overlapPercentage": 20},
            }
        },
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


def _run_ingestion_job(ctx, kb_id: str, ds_id: str, leg: str) -> dict:
    """Start one ingestion job, wait for COMPLETE, and return its statistics.

    RAISES on FAILED and on timeout. The terminal set excludes FAILED so a failed job can never
    be mistaken for convergence.
    """
    bedrock = ctx.client("bedrock-agent")
    job_id = bedrock.start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id)[
        "ingestionJob"
    ]["ingestionJobId"]

    deadline = time.monotonic() + 420.0
    last = None
    while time.monotonic() < deadline:
        last = bedrock.get_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )["ingestionJob"]
        if last["status"] == "FAILED":
            raise AssertionError(
                f"ingestion job {job_id} ({leg}) reached FAILED: {last.get('failureReasons')}"
            )
        if last["status"] == "COMPLETE":
            stats = last["statistics"]
            missing = [f for f in _STAT_FIELDS if f not in stats]
            assert not missing, (
                f"a COMPLETE ingestion job ({leg}) must report every documented statistic; "
                f"missing {missing} from {stats}"
            )
            return stats
        time.sleep(2)
    raise AssertionError(
        f"ingestion job {job_id} ({leg}) never reached COMPLETE within 420s; last status="
        f"{None if last is None else last.get('status')!r}"
    )


def _document_statuses(ctx, kb_id: str, ds_id: str) -> dict:
    """Map document identifier -> status via ListKnowledgeBaseDocuments (paginated)."""
    bedrock = ctx.client("bedrock-agent")
    statuses: dict[str, str] = {}
    token = None
    while True:
        kwargs = {"knowledgeBaseId": kb_id, "dataSourceId": ds_id, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = bedrock.list_knowledge_base_documents(**kwargs)
        for detail in resp["documentDetails"]:
            identifier = detail["identifier"]
            key = identifier.get("s3", {}).get("uri") or json.dumps(identifier, sort_keys=True)
            statuses[key] = detail["status"]
        token = resp.get("nextToken")
        if not token:
            return statuses


def _list_ingestion_jobs(ctx, kb_id: str, ds_id: str) -> list:
    bedrock = ctx.client("bedrock-agent")
    jobs = []
    token = None
    while True:
        kwargs = {"knowledgeBaseId": kb_id, "dataSourceId": ds_id, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = bedrock.list_ingestion_jobs(**kwargs)
        jobs.extend(resp["ingestionJobSummaries"])
        token = resp.get("nextToken")
        if not token:
            return jobs


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
