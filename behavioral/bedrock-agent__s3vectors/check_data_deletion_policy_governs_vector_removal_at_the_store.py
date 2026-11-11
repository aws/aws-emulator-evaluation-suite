"""data-deletion-policy-governs-vector-removal-at-the-store."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "data-deletion-policy-governs-vector-removal-at-the-store"
GROUP = "cross-service"
SERVICES = ["bedrock-agent", "s3vectors"]

_EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
_EMBEDDING_DIMENSION = 1024

# Deliberately different document counts per arm (every subset sum distinct), so the arithmetic
# below cannot be satisfied by a target that removes the wrong arm's vectors.
_RETAIN_DOCUMENTS = 2
_DELETE_DOCUMENTS = 3
_CONTROL_DOCUMENTS = 4
#: Bound on a data source delete reaching not-found, and on its vectors leaving the index.
_DELETE_CONVERGE_S = 300.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """dataDeletionPolicy is enforced at the vector store: deleting a DELETE-policy data source
    removes its vectors from the S3 Vectors index while a RETAIN-policy twin's vectors survive its
    own deletion, shown against a DELETE-policy control deleted after it."""
    account_id, partition = _caller_identity(ctx)
    store = _create_vector_store(ctx, account_id, partition)
    retain_bucket, retain_bucket_arn = _create_source_bucket(ctx, "retain")
    delete_bucket, delete_bucket_arn = _create_source_bucket(ctx, "delete")
    control_bucket, control_bucket_arn = _create_source_bucket(ctx, "control")

    _upload_documents(ctx, retain_bucket, _RETAIN_DOCUMENTS, "retain")
    _upload_documents(ctx, delete_bucket, _DELETE_DOCUMENTS, "delete")
    _upload_documents(ctx, control_bucket, _CONTROL_DOCUMENTS, "control")

    kb_id = _create_kb(
        ctx, account_id, partition, store, [retain_bucket_arn, delete_bucket_arn, control_bucket_arn]
    )

    # An empty index is the baseline every later count is measured against.
    baseline = _count_vectors(ctx, store)
    assert baseline == 0, (
        f"the freshly created vector index must be empty before any ingestion, got {baseline} "
        f"vectors -- every count assertion below is relative to this baseline"
    )

    retain_ds = _create_data_source(ctx, kb_id, retain_bucket_arn, "retain", "RETAIN")
    delete_ds = _create_data_source(ctx, kb_id, delete_bucket_arn, "delete", "DELETE")
    control_ds = _create_data_source(ctx, kb_id, control_bucket_arn, "control", "DELETE")

    # The control-plane round trip first: the policy must be stored as given, or nothing below
    # is testing what it claims to test.
    for ds_id, expected in ((retain_ds, "RETAIN"), (delete_ds, "DELETE"), (control_ds, "DELETE")):
        stored = ctx.client("bedrock-agent").get_data_source(
            knowledgeBaseId=kb_id, dataSourceId=ds_id
        )["dataSource"]["dataDeletionPolicy"]
        assert stored == expected, (
            f"data source {ds_id} must store dataDeletionPolicy={expected}, got {stored!r}"
        )

    # ---- Ingest the RETAIN arm and measure its contribution --------------------------------
    _run_ingestion_job(ctx, kb_id, retain_ds, _RETAIN_DOCUMENTS, "RETAIN arm ingestion")
    after_retain = _count_vectors(ctx, store)
    n_retain = after_retain - baseline
    assert n_retain >= _RETAIN_DOCUMENTS, (
        f"the RETAIN data source's {_RETAIN_DOCUMENTS} documents must produce at least one vector "
        f"each in the index: expected >= {_RETAIN_DOCUMENTS} new vectors, got {n_retain}"
    )

    # ---- Ingest the DELETE arm and measure its contribution -------------------------------
    _run_ingestion_job(ctx, kb_id, delete_ds, _DELETE_DOCUMENTS, "DELETE arm ingestion")
    after_both = _count_vectors(ctx, store)
    n_delete = after_both - after_retain
    assert n_delete >= _DELETE_DOCUMENTS, (
        f"the DELETE data source's {_DELETE_DOCUMENTS} documents must produce at least one vector "
        f"each: expected >= {_DELETE_DOCUMENTS} further vectors, got {n_delete}"
    )
    assert after_both == n_retain + n_delete, (
        f"the index must hold both arms' vectors: expected {n_retain} + {n_delete} = "
        f"{n_retain + n_delete}, got {after_both}"
    )

    # ---- Ingest the control arm (DELETE policy, deleted last) ---------------------------------
    _run_ingestion_job(ctx, kb_id, control_ds, _CONTROL_DOCUMENTS, "control arm ingestion")
    after_all = _count_vectors(ctx, store)
    n_control = after_all - after_both
    assert n_control >= _CONTROL_DOCUMENTS, (
        f"the control data source's {_CONTROL_DOCUMENTS} documents must produce at least one "
        f"vector each: expected >= {_CONTROL_DOCUMENTS} further vectors, got {n_control}"
    )

    # ---- The DELETE arm: deleting the data source must remove its vectors -------------------
    # Terminal read is at the CONSUMER (S3 Vectors ListVectors), through a different service
    # entirely from the bedrock-agent DeleteDataSource that caused it.
    ctx.client("bedrock-agent").delete_data_source(knowledgeBaseId=kb_id, dataSourceId=delete_ds)
    _wait_vector_count(ctx, store, n_retain + n_control, "the DELETE-policy data source")

    # ---- The RETAIN arm: deleting it must NOT remove its vectors -----------------------------
    # Absence by contrast: the RETAIN data source is deleted and gone first, then the DELETE-policy
    # control is deleted; once the control's vectors have left, the RETAIN vectors must remain.
    ctx.client("bedrock-agent").delete_data_source(knowledgeBaseId=kb_id, dataSourceId=retain_ds)
    _wait_data_source_gone(ctx, kb_id, retain_ds)
    ctx.client("bedrock-agent").delete_data_source(knowledgeBaseId=kb_id, dataSourceId=control_ds)
    _wait_vector_count(ctx, store, n_retain, "the DELETE-policy control data source")

    # A second independent observable at the consumer, not just a count: the vectors are still
    # individually retrievable, so "retained" means usable rather than merely counted.
    keys = _list_vector_keys(ctx, store)
    assert len(keys) == n_retain, (
        f"ListVectors must still enumerate the retained vectors: expected {n_retain} keys, got "
        f"{len(keys)}"
    )
    fetched = ctx.client("s3vectors").get_vectors(
        vectorBucketName=store["bucket"],
        indexName=store["index"],
        keys=keys[: min(2, len(keys))],
    )["vectors"]
    assert len(fetched) == min(2, len(keys)), (
        f"the retained vectors must still be readable at the store: asked for "
        f"{min(2, len(keys))} keys, got {len(fetched)}"
    )


import json  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402


def _swallow_not_found(fn) -> None:
    """Cleanup helper: a resource already gone is not a teardown failure, anything else is."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "NotFoundException",
            "NoSuchBucket",
        ):
            raise


def _caller_identity(ctx) -> tuple[str, str]:
    identity = ctx.client("sts").get_caller_identity()
    return identity["Account"], identity["Arn"].split(":")[1]


def _create_source_bucket(ctx, arm: str) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-ddp-{arm}-").lower()
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


def _upload_documents(ctx, bucket: str, count: int, arm: str) -> None:
    s3 = ctx.client("s3")
    for i in range(count):
        s3.put_object(
            Bucket=bucket,
            Key=f"{arm}-doc-{i:02d}.txt",
            Body=(
                f"Sample document {i} for the {arm} data deletion policy arm. This "
                f"paragraph gives the ingestion pipeline real text to chunk and embed so that a "
                f"vector actually lands in the bound S3 Vectors index for arm {arm}."
            ).encode(),
            ContentType="text/plain",
        )
    listed = sorted(
        obj["Key"] for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    )
    assert len(listed) == count, (
        f"the {arm} source prefix must hold exactly {count} documents, got {len(listed)}: {listed}"
    )


def _create_vector_store(ctx, account_id: str, partition: str) -> dict:
    s3vectors = ctx.client("s3vectors")
    bucket = ctx.unique_name("sim2real-ddp-vec-").lower()
    index = ctx.unique_name("sim2real-ddp-idx-").lower()
    s3vectors.create_vector_bucket(vectorBucketName=bucket)
    ctx.on_cleanup(
        lambda: _swallow_not_found(lambda: s3vectors.delete_vector_bucket(vectorBucketName=bucket))
    )
    s3vectors.create_index(
        vectorBucketName=bucket,
        indexName=index,
        dataType="float32",
        dimension=_EMBEDDING_DIMENSION,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: s3vectors.delete_index(vectorBucketName=bucket, indexName=index)
        )
    )
    bucket_arn = f"arn:{partition}:s3vectors:{ctx.region}:{account_id}:bucket/{bucket}"
    return {
        "bucket": bucket,
        "index": index,
        "bucket_arn": bucket_arn,
        "index_arn": f"{bucket_arn}/index/{index}",
    }


def _list_vector_keys(ctx, store: dict) -> list:
    """Every vector key currently in the index (paginated)."""
    s3vectors = ctx.client("s3vectors")
    keys: list[str] = []
    token = None
    while True:
        kwargs = {
            "vectorBucketName": store["bucket"],
            "indexName": store["index"],
            "maxResults": 500,
        }
        if token:
            kwargs["nextToken"] = token
        resp = s3vectors.list_vectors(**kwargs)
        keys.extend(vector["key"] for vector in resp["vectors"])
        token = resp.get("nextToken")
        if not token:
            return keys


def _count_vectors(ctx, store: dict) -> int:
    return len(_list_vector_keys(ctx, store))


def _create_kb(ctx, account_id: str, partition: str, store: dict, source_bucket_arns: list) -> str:
    bedrock = ctx.client("bedrock-agent")
    embedding_model_arn = (
        f"arn:{partition}:bedrock:{ctx.region}::foundation-model/{_EMBEDDING_MODEL}"
    )
    role_arn = _create_kb_role(
        ctx, account_id, partition, store, source_bucket_arns, embedding_model_arn
    )

    deadline = time.monotonic() + 120.0
    kb_id = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            kb_id = bedrock.create_knowledge_base(
                name=ctx.unique_name("sim2real-ddp-kb-"),
                roleArn=role_arn,
                knowledgeBaseConfiguration={
                    "type": "VECTOR",
                    "vectorKnowledgeBaseConfiguration": {
                        "embeddingModelArn": embedding_model_arn
                    },
                },
                storageConfiguration={
                    "type": "S3_VECTORS",
                    "s3VectorsConfiguration": {
                        "vectorBucketArn": store["bucket_arn"],
                        "indexArn": store["index_arn"],
                    },
                },
                tags={"sim2real-check": CHECK},
            )["knowledgeBase"]["knowledgeBaseId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            last_exc = exc
            time.sleep(5)  # bounded: inside a deadline-guarded IAM-propagation retry
    if kb_id is None:
        raise AssertionError(
            f"CreateKnowledgeBase never succeeded within 120s of role-propagation retries; "
            f"last error={last_exc}"
        )
    captured_kb_id = kb_id
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: bedrock.delete_knowledge_base(knowledgeBaseId=captured_kb_id)
        )
    )

    status_deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < status_deadline:
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
    ctx, account_id, partition, store, source_bucket_arns, embedding_model_arn
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ddp-role-")
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

    object_arns = []
    for arn in source_bucket_arns:
        object_arns.extend([arn, f"{arn}/*"])
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
                        "Resource": [store["bucket_arn"], store["index_arn"]],
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": object_arns,
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


def _create_data_source(ctx, kb_id: str, bucket_arn: str, arm: str, policy: str) -> str:
    bedrock = ctx.client("bedrock-agent")
    ds_id = bedrock.create_data_source(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name(f"sim2real-ddp-{arm}-ds-"),
        dataSourceConfiguration={"type": "S3", "s3Configuration": {"bucketArn": bucket_arn}},
        dataDeletionPolicy=policy,
        vectorIngestionConfiguration={
            "chunkingConfiguration": {
                "chunkingStrategy": "FIXED_SIZE",
                "fixedSizeChunkingConfiguration": {"maxTokens": 300, "overlapPercentage": 20},
            }
        },
    )["dataSource"]["dataSourceId"]
    # The body deletes every data source as the subject of the check, but cleanup is still
    # registered: DeleteKnowledgeBase can conflict while data sources remain, so if the body
    # fails before its own deletes the KB teardown would leak. _swallow_not_found makes the
    # double delete safe on the happy path.
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
            raise AssertionError(
                f"{arm} data source {ds_id} reached FAILED instead of AVAILABLE"
            )
        if last == "AVAILABLE":
            return ds_id
        time.sleep(5)
    raise AssertionError(
        f"{arm} data source {ds_id} never reached AVAILABLE within 120s; last status={last!r}"
    )


def _run_ingestion_job(ctx, kb_id: str, ds_id: str, document_count: int, leg: str) -> dict:
    """Start one ingestion job and wait for COMPLETE. RAISES on FAILED and on timeout."""
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
            assert stats["numberOfDocumentsFailed"] == 0, (
                f"{leg}: no document may fail, or the vector counts below are not attributable; "
                f"numberOfDocumentsFailed={stats['numberOfDocumentsFailed']}"
            )
            assert stats["numberOfNewDocumentsIndexed"] == document_count, (
                f"{leg}: expected all {document_count} documents to be indexed as new, got "
                f"numberOfNewDocumentsIndexed={stats['numberOfNewDocumentsIndexed']}"
            )
            return last
        time.sleep(2)
    raise AssertionError(
        f"ingestion job {job_id} ({leg}) never reached COMPLETE within 420s; last status="
        f"{None if last is None else last.get('status')!r}"
    )


def _deadline(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return time.monotonic() + (cap_s if left is None else max(1.0, min(cap_s, left - 5.0)))


def _wait_vector_count(ctx, store: dict, expected: int, deleted: str) -> None:
    """Poll the index until it holds ``expected`` vectors after ``deleted`` was deleted; a count
    below ``expected`` means the delete removed vectors it did not write, and fails at once."""
    deadline = _deadline(ctx, _DELETE_CONVERGE_S)
    while True:
        observed = _count_vectors(ctx, store)
        if observed == expected:
            return
        assert observed > expected, (
            f"deleting {deleted} removed MORE than its own vectors: the index dropped to "
            f"{observed}, below the {expected} vectors of the data sources that must remain"
        )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"deleting {deleted} did not remove its vectors from the index within "
                f"{_DELETE_CONVERGE_S:.0f}s: expected the count to fall to {expected}, still {observed}"
            )
        time.sleep(2)


def _wait_data_source_gone(ctx, kb_id: str, ds_id: str) -> None:
    """Poll GetDataSource until the deleted data source is not-found."""
    bedrock = ctx.client("bedrock-agent")
    deadline = _deadline(ctx, _DELETE_CONVERGE_S)
    while True:
        try:
            status = bedrock.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)[
                "dataSource"
            ]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"data source {ds_id} is still {status} {_DELETE_CONVERGE_S:.0f}s after its delete"
            )
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
