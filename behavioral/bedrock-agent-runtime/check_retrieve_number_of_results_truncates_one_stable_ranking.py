"""retrieve-number-of-results-truncates-one-stable-ranking."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retrieve-number-of-results-truncates-one-stable-ranking"
GROUP = "ordering"
SERVICES = ["bedrock-agent-runtime"]

_EMBED_MODEL_ID = "amazon.titan-embed-text-v2:0"
_EMBED_DIM = 1024

# Modelled KnowledgeBaseVectorSearchConfiguration constraints -- fixed API constants, not
# account quotas, so pinning them is correct.
_NOR_MIN = 1
_NOR_MAX = 100
_NOR_DEFAULT = 5

# Six topically disjoint source documents. _DOC_COUNT is DERIVED from the list rather than
# asserted equal to it, so there is no assertion over constants.
_PROJECTS = ("Falcon", "Osprey", "Kestrel", "Merlin", "Harrier", "Condor")
_DOC_COUNT = len(_PROJECTS)
_PROBE = "Which launch code belongs to which project?"

# Bounds for KB activation, data source creation, ingestion and IAM propagation.
_KB_ACTIVE_S = 180.0
_DS_S = 90.0
_INGEST_S = 300.0
_IAM_S = 90.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """numberOfResults truncates one stable Retrieve ranking: the top-1 is the head of the top-3,
    scores are non-increasing, the default is 5, and the 1..100 range is enforced."""
    runtime = ctx.client("bedrock-agent-runtime")
    # The rejection leg pushes numberOfResults outside the modelled 1..100 range on purpose. That
    # range is also enforced by botocore's OWN client-side validator (it reads the same Smithy
    # min/max), so the plain client raises a local ParamValidationError and the malformed request
    # never reaches AWS, and a local ParamValidationError is not the service's rejection. This
    # client disables that local check so the request is actually sent, and the code asserted below
    # is the SERVICE's, not the SDK's.
    unvalidated = ctx.client("bedrock-agent-runtime", config=Config(parameter_validation=False))

    tokens, uris = _ingest_documents(ctx)
    kb_id = _create_s3vectors_knowledge_base(ctx, sorted(uris)[0].split("/")[2])

    def _retrieve(number_of_results: int | None, *, client=None) -> list[dict]:
        kwargs: dict = dict(knowledgeBaseId=kb_id, retrievalQuery={"text": _PROBE})
        if number_of_results is not None:
            kwargs["retrievalConfiguration"] = {
                "vectorSearchConfiguration": {"numberOfResults": number_of_results}
            }
        return (client or runtime).retrieve(**kwargs)["retrievalResults"]

    def _identity(results: list[dict]) -> list[tuple[str, str]]:
        """A result's stable identity: where it came from plus the bytes it carries."""
        return [(r["location"]["s3Location"]["uri"], r["content"]["text"]) for r in results]

    # ---- the bound, and the positive control that Retrieve works at all here.
    top3 = _retrieve(3)
    assert len(top3) == 3, (
        f"with {_DOC_COUNT} ingested documents, Retrieve(numberOfResults=3) must return exactly "
        f"3 results; got {len(top3)}. If the real chunk count is below 3 this is a chunking "
        f"difference: sources returned were {sorted({r['location']['s3Location']['uri'] for r in top3})}"
    )
    _assert_sources(top3, uris, label="numberOfResults=3")

    # ---- non-increasing score.
    scores3 = [r["score"] for r in top3]
    assert scores3 == sorted(scores3, reverse=True), (
        f"Retrieve must return results ordered by non-increasing relevance score; got {scores3} "
        f"for sources {[r['location']['s3Location']['uri'] for r in top3]}"
    )

    # ---- the lower boundary, and truncation, not reselection. This is the discriminating leg.
    top1 = _retrieve(_NOR_MIN)
    assert len(top1) == 1, (
        f"Retrieve(numberOfResults={_NOR_MIN}) must return exactly 1 result; got {len(top1)}"
    )
    assert _identity(top1) == _identity(top3)[:1], (
        f"numberOfResults must TRUNCATE one ranking, not select a different set: "
        f"numberOfResults=1 returned {_identity(top1)[0][0]!r} while the head of the "
        f"numberOfResults=3 ranking was {_identity(top3)[0][0]!r}"
    )
    assert top1[0]["score"] == top3[0]["score"], (
        f"the same chunk must carry the same score across calls with different numberOfResults: "
        f"{top1[0]['score']} vs {top3[0]['score']} for {_identity(top1)[0][0]!r}"
    )

    # ---- the modelled default really applies when retrievalConfiguration is omitted.
    default_results = _retrieve(None)
    assert len(default_results) == _NOR_DEFAULT, (
        f"omitting retrievalConfiguration must apply the modelled default numberOfResults="
        f"{_NOR_DEFAULT}, so with {_DOC_COUNT} chunks available the call must return exactly "
        f"{_NOR_DEFAULT} results; got {len(default_results)}. A target that returns every chunk "
        f"({_DOC_COUNT}) or only one is not applying the default"
    )
    assert len(default_results) >= len(top3), (
        f"the default result count ({len(default_results)}) must be at least the explicit "
        f"numberOfResults=3 count ({len(top3)})"
    )
    assert _identity(default_results)[:3] == _identity(top3), (
        f"the default-sized ranking must share its head with the numberOfResults=3 ranking: "
        f"{_identity(default_results)[:3]} vs {_identity(top3)}"
    )
    _assert_sources(default_results, uris, label="default numberOfResults")

    # ---- Positive control at the inclusive maximum, BEFORE the two rejections, so
    # "rejects 101" is distinguishable from "rejects anything large".
    at_max = _retrieve(_NOR_MAX)
    assert len(at_max) >= len(default_results), (
        f"numberOfResults={_NOR_MAX} is the inclusive modelled maximum and must be accepted, "
        f"returning at least as many results as the default; got {len(at_max)} vs "
        f"{len(default_results)}"
    )
    assert len(at_max) <= _NOR_MAX, (
        f"numberOfResults={_NOR_MAX} returned {len(at_max)} results, more than requested"
    )
    _assert_sources(at_max, uris, label=f"numberOfResults={_NOR_MAX}")
    chunk_count = len(at_max)

    # ---- Rejections. ALWAYS-INVALID-INPUT: 0 and 101 can never become valid, so there is no
    # restore beat by construction.
    below, below_message = _error(lambda: _retrieve(_NOR_MIN - 1, client=unvalidated))
    assert below == "ValidationException", (
        f"numberOfResults={_NOR_MIN - 1} is below the modelled minimum {_NOR_MIN} and must be "
        f"rejected with ValidationException; got {below!r}"
    )
    assert below_message == (
        f"1 validation error detected: Value '{_NOR_MIN - 1}' at "
        "'retrievalConfiguration.vectorSearchConfiguration.numberOfResults' failed to satisfy "
        f"constraint: Member must have value greater than or equal to {_NOR_MIN}"
    ), f"unexpected numberOfResults={_NOR_MIN - 1} message: {below_message!r}"
    above, above_message = _error(lambda: _retrieve(_NOR_MAX + 1, client=unvalidated))
    assert above == "ValidationException", (
        f"numberOfResults={_NOR_MAX + 1} is above the modelled maximum {_NOR_MAX} and must be "
        f"rejected with ValidationException; got {above!r}"
    )
    assert above_message == (
        f"1 validation error detected: Value '{_NOR_MAX + 1}' at "
        "'retrievalConfiguration.vectorSearchConfiguration.numberOfResults' failed to satisfy "
        f"constraint: Member must have value less than or equal to {_NOR_MAX}"
    ), f"unexpected numberOfResults={_NOR_MAX + 1} message: {above_message!r}"

    # Effect-absent for the rejections: nothing about the knowledge base changed, so the
    # identical accepted call still returns the identical ranking.
    after_reject = _retrieve(3)
    assert _identity(after_reject) == _identity(top3), (
        f"two rejected Retrieve calls must leave the knowledge base untouched, but the "
        f"numberOfResults=3 ranking changed from {_identity(top3)} to {_identity(after_reject)}"
    )

    # ---- Freeze detector: retrieval is a read, so N identical reads return N identical
    # answers. This is what an emulator doing a fresh randomised ANN search per call fails, and
    # it is asserted with no timing assumption at all.
    baseline_identity = _identity(top3)
    for attempt in range(3):
        again = _retrieve(3)
        assert _identity(again) == baseline_identity, (
            f"repeat Retrieve #{attempt + 1} with an identical query and configuration returned a "
            f"different ranking: {_identity(again)} != {baseline_identity}"
        )
        assert [r["score"] for r in again] == scores3, (
            f"repeat Retrieve #{attempt + 1} returned different scores: "
            f"{[r['score'] for r in again]} != {scores3}"
        )

    # ---- Terminal read: an independent operation at the control plane, on a different client,
    # proving 8 data-plane retrievals did not advance the knowledge base's state.
    kb = ctx.client("bedrock-agent").get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
    assert kb["status"] == "ACTIVE", (
        f"after {8} Retrieve calls (6 accepted, 2 rejected) the knowledge base must still be "
        f"ACTIVE; got {kb['status']!r}"
    )
    assert chunk_count >= _NOR_DEFAULT, (
        f"chunking check: the knowledge base served only {chunk_count} chunk(s) from {_DOC_COUNT} "
        f"ingested documents carrying tokens {sorted(tokens)}, so the exact counts asserted "
        f"above rest on a chunking assumption that did not hold"
    )



def _assert_sources(results: list[dict], uris: set[str], *, label: str) -> None:
    """Every result names a source this check actually ingested."""
    for idx, result in enumerate(results):
        location = result["location"]
        assert location["type"] == "S3", (
            f"{label} result {idx}: the data source is S3, so location.type must be 'S3'; got "
            f"{location['type']!r}"
        )
        uri = location["s3Location"]["uri"]
        assert uri in uris, (
            f"{label} result {idx}: location.s3Location.uri={uri!r} is not one of the "
            f"{len(uris)} objects this check ingested {sorted(uris)}"
        )
        assert result["content"]["text"], f"{label} result {idx}: content.text is empty"


def _ingest_documents(ctx) -> tuple[set[str], set[str]]:
    """Six short S3 objects, each with a distinct per-run nonce token, so no fixed response can
    carry the expected values and no model prior knowledge can supply them."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-norsrc-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 is the only region where CreateBucket must omit LocationConstraint.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _quiet(lambda: s3.delete_bucket(Bucket=bucket)))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK[:250]}]}
    )

    tokens: set[str] = set()
    uris: set[str] = set()
    for project in _PROJECTS:
        token = ctx.unique_name(f"CODE{project.upper()}").upper()
        tokens.add(token)
        body = (
            f"Project {project} operations manual. The launch code for Project {project} is "
            f"{token}. Only the {project} launch team may use this launch code."
        )
        key = f"project-{project.lower()}.txt"
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=body.encode("utf-8"),
            ContentType="text/plain",
            Tagging=f"sim2real-check={CHECK[:250]}",
        )
        ctx.on_cleanup(lambda k=key: _quiet(lambda: s3.delete_object(Bucket=bucket, Key=k)))
        uris.add(f"s3://{bucket}/{key}")
    return tokens, uris


def _create_s3vectors_knowledge_base(ctx, bucket: str) -> str:
    """S3-Vectors-backed knowledge base over `bucket`, ingested."""
    ba = ctx.client("bedrock-agent")
    s3v = ctx.client("s3vectors")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_arn = f"arn:aws:s3:::{bucket}"

    vector_bucket = ctx.unique_name("sim2real-norvb-").lower()
    s3v.create_vector_bucket(vectorBucketName=vector_bucket)
    ctx.on_cleanup(lambda: _quiet(lambda: s3v.delete_vector_bucket(vectorBucketName=vector_bucket)))
    vector_bucket_arn = s3v.get_vector_bucket(vectorBucketName=vector_bucket)["vectorBucket"][
        "vectorBucketArn"
    ]

    index_name = ctx.unique_name("sim2real-norvi-").lower()
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
            name=ctx.unique_name("sim2real-norkb-"),
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
        name=ctx.unique_name("sim2real-nords-"),
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
        description="ingestion job COMPLETE (terminal set excludes FAILED and STOPPED so a "
        "failed ingestion times out loudly instead of yielding an empty index)",
    )
    return kb_id


def _create_kb_role(ctx, account_id: str, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-norkbrole-")
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

    policy_name = "sim2real-norkb-policy"
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


def _error(fn) -> tuple[str, str]:
    """Return the ClientError (code, message), or RAISE on unexpected success. Never returns a falsy
    sentinel, which would turn an over-permissive target's acceptance into a mere code
    mismatch."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry that RAISES on timeout (never returns its last value)."""
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
