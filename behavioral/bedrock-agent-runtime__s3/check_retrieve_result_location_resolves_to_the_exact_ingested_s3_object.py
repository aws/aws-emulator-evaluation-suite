"""retrieve-result-location-resolves-to-the-exact-ingested-s3-object."""
from __future__ import annotations

import hashlib
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retrieve-result-location-resolves-to-the-exact-ingested-s3-object"
GROUP = "arn-resolution"
SERVICES = ["bedrock-agent-runtime", "s3"]

_EMBED_MODEL_ID = "amazon.titan-embed-text-v2:0"
_EMBED_DIM = 1024
# The metadata keys of an S3 data source result; AWS sets no "source-uri" key.
_DATA_SOURCE_ID_METADATA_KEY = "x-amz-bedrock-kb-data-source-id"
_MODALITY_METADATA_KEY = "x-amz-bedrock-kb-source-file-modality"
_CHUNK_ID_METADATA_KEY = "x-amz-bedrock-kb-chunk-id"

# Bounds for KB activation, data-source creation, ingestion of two small objects, IAM propagation.
_KB_ACTIVE_S = 180.0
_DS_S = 90.0
_INGEST_S = 300.0
_IAM_S = 90.0

_S3_URI_RE = re.compile(r"^s3://(?P<bucket>[^/]+)/(?P<key>.+)$")
_WS_RE = re.compile(r"\s+")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every Retrieve result's s3Location.uri names the ingested object whose bytes contain the chunk.

    Metadata names the check's data source; after the object is deleted Retrieve still cites it.
    """
    runtime = ctx.client("bedrock-agent-runtime")
    s3 = ctx.client("s3")

    bucket, objects = _ingest_two_documents(ctx)
    kb_id, ds_id = _create_s3vectors_knowledge_base(ctx, bucket)

    results = runtime.retrieve(
        knowledgeBaseId=kb_id,
        retrievalQuery={"text": "Which launch code belongs to which project?"},
        retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": 5}},
    )["retrievalResults"]
    assert len(results) >= 1, (
        f"Retrieve returned 0 results against a knowledge base this check ingested "
        f"{len(objects)} document(s) into; without a result there is no location to resolve"
    )

    resolved: set[str] = set()
    chunk_ids: set[str] = set()
    for idx, result in enumerate(results):
        location = result["location"]
        assert location["type"] == "S3", (
            f"result {idx}: the data source is S3, so location.type must be 'S3'; got "
            f"{location['type']!r} (H1)"
        )
        uri = location["s3Location"]["uri"]
        match = _S3_URI_RE.match(uri)
        assert match, (
            f"result {idx}: location.s3Location.uri={uri!r} is not of the form s3://<bucket>/<key> "
            f"and cannot be resolved at S3 (H1)"
        )
        got_bucket, got_key = match.group("bucket"), match.group("key")
        assert got_bucket == bucket, (
            f"result {idx}: the citation names bucket {got_bucket!r} but this check ingested from "
            f"{bucket!r}; the location points somewhere it was never given (H1)"
        )
        assert got_key in objects, (
            f"result {idx}: the citation names key {got_key!r}, which is not one of the "
            f"{len(objects)} objects this check uploaded {sorted(objects)} (H1)"
        )
        resolved.add(got_key)
        expected = objects[got_key]

        # ---- The cited object exists at S3 with the bytes this check uploaded. Under default
        # SSE-KMS the ETag would not be the MD5; the GetObject body hash covers that case.
        head = s3.head_object(Bucket=got_bucket, Key=got_key)
        etag = head["ETag"].strip('"')
        assert etag == expected["md5"], (
            f"result {idx}: the cited object s3://{got_bucket}/{got_key} has ETag {etag!r} but the "
            f"bytes this check uploaded hash to {expected['md5']!r}. Either the citation names a "
            f"different object or the object was rewritten. (If this account applies default "
            f"SSE-KMS, the ETag is not the MD5 -- see H2.)"
        )
        body = s3.get_object(Bucket=got_bucket, Key=got_key)["Body"].read()
        assert hashlib.md5(body).hexdigest() == expected["md5"], (
            f"result {idx}: GetObject on the cited object returned bytes hashing to "
            f"{hashlib.md5(body).hexdigest()!r}, not the uploaded {expected['md5']!r} (H2)"
        )

        # ---- The chunk is a span of those bytes. Chunking may reflow whitespace, so the
        # comparison collapses it, but stays a substring test rather than token containment.
        chunk_text = result["content"]["text"]
        assert chunk_text, f"result {idx}: content.text is empty"
        flat_chunk = _WS_RE.sub(" ", chunk_text).strip()
        flat_body = _WS_RE.sub(" ", body.decode("utf-8")).strip()
        assert flat_chunk in flat_body, (
            f"result {idx}: the retrieved chunk is not a substring of the real bytes of the object "
            f"it cites (s3://{got_bucket}/{got_key}). Chunk (whitespace-collapsed) was "
            f"{flat_chunk[:200]!r}; object body was {flat_body[:200]!r} (H3)"
        )

        # ---- No cross-attribution. The other document's nonce must not be in this chunk.
        for other_key, other in objects.items():
            if other_key == got_key:
                continue
            assert other["nonce"] not in chunk_text, (
                f"result {idx} is attributed to {got_key!r} but its text contains "
                f"{other['nonce']!r}, which appears only in {other_key!r}; the chunk is "
                f"cross-attributed (H4)"
            )

        # ---- Metadata ties the citation to the data source this check created and to the
        # plain-text object type, and carries a chunk id unique across this result set.
        metadata = result["metadata"]
        assert metadata.get(_DATA_SOURCE_ID_METADATA_KEY) == ds_id, (
            f"result {idx}: metadata[{_DATA_SOURCE_ID_METADATA_KEY!r}]="
            f"{metadata.get(_DATA_SOURCE_ID_METADATA_KEY)!r} does not name the data source "
            f"{ds_id!r} this check created; keys present were {sorted(metadata)} (H5)"
        )
        assert metadata.get(_MODALITY_METADATA_KEY) == "TEXT", (
            f"result {idx}: metadata[{_MODALITY_METADATA_KEY!r}]="
            f"{metadata.get(_MODALITY_METADATA_KEY)!r}, expected 'TEXT' for the plain-text "
            f"objects this check uploaded (H5)"
        )
        chunk_id = metadata.get(_CHUNK_ID_METADATA_KEY)
        assert chunk_id, (
            f"result {idx}: metadata must carry a non-empty {_CHUNK_ID_METADATA_KEY!r}; keys "
            f"present were {sorted(metadata)} (H5)"
        )
        assert chunk_id not in chunk_ids, (
            f"result {idx}: {_CHUNK_ID_METADATA_KEY}={chunk_id!r} repeats an earlier result's "
            f"chunk id in the same Retrieve call; chunk ids must be unique per result (H5)"
        )
        chunk_ids.add(chunk_id)

    assert resolved, "no result carried a resolvable S3 location"

    # ---- Deleting one of this check's own objects makes the citation dangle at S3.
    victim = sorted(resolved)[0]
    s3.delete_object(Bucket=bucket, Key=victim)
    code = _error_code(lambda: s3.head_object(Bucket=bucket, Key=victim))
    assert code == "404", (
        f"after deleting s3://{bucket}/{victim}, HeadObject must fail with a 404; got {code!r}. "
        f"(botocore reports HeadObject's not-found as the bare status code, not "
        f"'NoSuchKey' -- if the replay shows otherwise, record the real code.) (H6)"
    )

    # Retrieve still cites the deleted object: the vectors were ingested, so deleting the source
    # does not retroactively rewrite the index.
    after = runtime.retrieve(
        knowledgeBaseId=kb_id,
        retrievalQuery={"text": "Which launch code belongs to which project?"},
        retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": 5}},
    )["retrievalResults"]
    still_cited = {
        _S3_URI_RE.match(r["location"]["s3Location"]["uri"]).group("key")
        for r in after
        if _S3_URI_RE.match(r["location"]["s3Location"]["uri"])
    }
    assert victim in still_cited, (
        f"deleting the source object must not retroactively rewrite the vector index, so Retrieve "
        f"must still cite {victim!r} (now a dangling reference); it cited {sorted(still_cited)} "
        f"instead. If real AWS DOES drop the chunk, that is a more interesting behaviour and this "
        f"hypothesis should be replaced with it (H6)"
    )


def _ingest_two_documents(ctx) -> tuple[str, dict]:
    """Two disjoint S3 objects, each with a per-run nonce, kept with their MD5 for an equality read."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-locsrc-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 is the only region where CreateBucket must omit LocationConstraint.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _quiet(lambda: s3.delete_bucket(Bucket=bucket)))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK[:250]}]}
    )

    objects: dict = {}
    for project in ("Falcon", "Osprey"):
        nonce = ctx.unique_name(f"CODE{project.upper()}").upper()
        body = (
            f"Project {project} operations manual. The launch code for Project {project} is "
            f"{nonce}. Only the {project} launch team may use this launch code."
        ).encode("utf-8")
        key = f"project-{project.lower()}.txt"
        # No SSE-KMS and a single-part put, so the ETag is the MD5 of the object.
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="text/plain",
            Tagging=f"sim2real-check={CHECK[:250]}",
        )
        ctx.on_cleanup(lambda k=key: _quiet(lambda: s3.delete_object(Bucket=bucket, Key=k)))
        objects[key] = {"nonce": nonce, "md5": hashlib.md5(body).hexdigest(), "body": body}
    return bucket, objects


def _create_s3vectors_knowledge_base(ctx, bucket: str) -> tuple[str, str]:
    """S3-Vectors-backed knowledge base over `bucket`, ingested.

    S3 Vectors rather than OpenSearch Serverless, whose collection alone can take minutes.
    """
    ba = ctx.client("bedrock-agent")
    s3v = ctx.client("s3vectors")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_arn = f"arn:aws:s3:::{bucket}"

    vector_bucket = ctx.unique_name("sim2real-locvb-").lower()
    s3v.create_vector_bucket(vectorBucketName=vector_bucket)
    ctx.on_cleanup(lambda: _quiet(lambda: s3v.delete_vector_bucket(vectorBucketName=vector_bucket)))
    vector_bucket_arn = s3v.get_vector_bucket(vectorBucketName=vector_bucket)["vectorBucket"][
        "vectorBucketArn"
    ]

    index_name = ctx.unique_name("sim2real-locvi-").lower()
    s3v.create_index(
        vectorBucketName=vector_bucket,
        indexName=index_name,
        dataType="float32",
        dimension=_EMBED_DIM,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(
        lambda: _quiet(lambda: s3v.delete_index(vectorBucketName=vector_bucket, indexName=index_name))
    )
    index_arn = s3v.get_index(vectorBucketName=vector_bucket, indexName=index_name)["index"]["indexArn"]

    role_arn = _create_kb_role(ctx, account_id, bucket_arn)
    embed_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/{_EMBED_MODEL_ID}"
    kb_id = _retry_on_role_propagation(
        lambda: ba.create_knowledge_base(
            name=ctx.unique_name("sim2real-lockb-"),
            roleArn=role_arn,
            knowledgeBaseConfiguration={
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {"embeddingModelArn": embed_arn},
            },
            storageConfiguration={
                "type": "S3_VECTORS",
                "s3VectorsConfiguration": {"vectorBucketArn": vector_bucket_arn, "indexArn": index_arn},
            },
            tags={"sim2real-check": CHECK[:250]},
        )
    )["knowledgeBase"]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _quiet(lambda: ba.delete_knowledge_base(knowledgeBaseId=kb_id)))
    _poll_until(
        lambda: ba.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=_KB_ACTIVE_S,
        interval_s=3.0,
        description="knowledge base status ACTIVE (terminal set excludes FAILED so a failed "
        "create times out loudly rather than being accepted)",
    )

    ds_id = ba.create_data_source(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-locds-"),
        dataSourceConfiguration={"type": "S3", "s3Configuration": {"bucketArn": bucket_arn}},
    )["dataSource"]["dataSourceId"]
    ctx.on_cleanup(
        lambda: _quiet(lambda: ba.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id))
    )
    _poll_until(
        lambda: ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]["status"],
        lambda s: s == "AVAILABLE",
        timeout_s=_DS_S,
        interval_s=3.0,
        description="data source status AVAILABLE",
    )

    job_id = ba.start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id)["ingestionJob"][
        "ingestionJobId"
    ]
    _poll_until(
        lambda: ba.get_ingestion_job(
            knowledgeBaseId=kb_id, dataSourceId=ds_id, ingestionJobId=job_id
        )["ingestionJob"]["status"],
        lambda s: s == "COMPLETE",
        timeout_s=_INGEST_S,
        interval_s=5.0,
        description="ingestion job COMPLETE (terminal set excludes FAILED and STOPPED so a failed "
        "ingestion times out loudly instead of yielding an empty index)",
    )
    return kb_id, ds_id


def _create_kb_role(ctx, account_id: str, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lockbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _quiet(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "sim2real-lockb-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": f"arn:aws:bedrock:{ctx.region}::foundation-model/{_EMBED_MODEL_ID}",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    },
                    {"Effect": "Allow", "Action": "s3vectors:*", "Resource": "*"},
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _quiet(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    return role_arn


def _error_code(fn) -> str:
    """Return the ClientError code, or RAISE on unexpected success."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry that RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last value: {last!r}")


def _retry_on_role_propagation(fn, *, timeout_s: float = _IAM_S, interval_s: float = 5.0):
    """IAM is eventually consistent; bounded, and RAISES on exhaustion."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"IAM role never propagated within {timeout_s}s: {last_exc}")


def _quiet(fn) -> None:
    """Teardown-only best effort. Never used on an assertion path."""
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
