"""retrieve-and-generate-citation-spans-index-the-generated-text."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retrieve-and-generate-citation-spans-index-the-generated-text"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]

_EMBED_MODEL_ID = "amazon.titan-embed-text-v2:0"
_EMBED_DIM = 1024
_GEN_MODEL_ID = "amazon.nova-lite-v1:0"

# Bounds for KB activation, data source creation, ingestion and IAM propagation.
_KB_ACTIVE_S = 180.0
_DS_S = 90.0
_INGEST_S = 300.0
_IAM_S = 90.0

_SESSION_ID_RE = re.compile(r"^[0-9a-zA-Z._:-]{2,100}$")  # modelled SessionId constraints


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every RetrieveAndGenerate citation's span.start indexes the generated output to exactly the
    cited text; only the last citation's span.end may stretch past it to len(output.text), and it
    points at a real ingested source."""
    runtime = ctx.client("bedrock-agent-runtime")

    tokens, uris = _ingest_two_documents(ctx)
    kb_id = _create_s3vectors_knowledge_base(ctx, sorted(uris)[0].split("/")[2])

    # ---- Positive control: Retrieve on this KB works. This proves the account, the credentials,
    # the KB and the embedding model are all healthy, so the subject call below is evidence about
    # generation specifically, not about a broken prerequisite.
    probe = (
        "Which project uses which launch code? Answer in exactly two separate sentences, "
        "one project per sentence, each ending with a period."
    )
    control = runtime.retrieve(
        knowledgeBaseId=kb_id,
        retrievalQuery={"text": probe},
        retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": 5}},
    )["retrievalResults"]
    assert len(control) >= 1, (
        f"positive control failed: Retrieve against the knowledge base this check just ingested "
        f"2 documents into returned 0 results for {probe!r}; without this control the subject "
        f"call below is not evidence of anything"
    )
    control_texts = " ".join(r["content"]["text"] for r in control)
    matched_control = [t for t in tokens if t in control_texts]
    assert matched_control, (
        f"positive control failed: none of the per-run nonce tokens {sorted(tokens)} appear in "
        f"the {len(control)} retrieved chunk(s); the knowledge base is not serving this check's "
        f"own ingested content"
    )

    # ---- Subject: RetrieveAndGenerate with a supported generation model on the same KB.
    model_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/{_GEN_MODEL_ID}"
    resp = runtime.retrieve_and_generate(
        input={"text": probe},
        retrieveAndGenerateConfiguration={
            "type": "KNOWLEDGE_BASE",
            "knowledgeBaseConfiguration": {
                "knowledgeBaseId": kb_id,
                "modelArn": model_arn,
                "retrievalConfiguration": {"vectorSearchConfiguration": {"numberOfResults": 5}},
            },
        },
    )

    # ---- The citation-span invariant.
    session_id = resp["sessionId"]
    assert _SESSION_ID_RE.match(session_id), (
        f"RetrieveAndGenerate must mint a sessionId matching the modelled SessionId constraints "
        f"(length 2..100, ^[0-9a-zA-Z._:-]+$); got {session_id!r}"
    )

    output_text = resp["output"]["text"]
    assert output_text, "RetrieveAndGenerate returned an empty output.text"

    citations = resp["citations"]
    assert len(citations) >= 1, (
        f"a grounded RetrieveAndGenerate answer over a knowledge base that returned "
        f"{len(control)} matching chunk(s) must carry at least one citation; got 0. Response "
        f"output was {output_text[:120]!r}"
    )

    n_citations = len(citations)
    spans: list[tuple[int, int, str]] = []
    for idx, citation in enumerate(citations):
        part = citation["generatedResponsePart"]["textResponsePart"]
        cited_text = part["text"]
        span = part["span"]
        start, end = span["start"], span["end"]

        assert 0 <= start <= end <= len(output_text), (
            f"citation {idx}: span [{start}, {end}] must satisfy 0 <= start <= end <= "
            f"len(output.text)={len(output_text)}"
        )

        prefix = output_text[start : start + len(cited_text)]
        assert prefix == cited_text, (
            f"citation {idx}: output.text[{start}:{start + len(cited_text)}]={prefix!r} does not "
            f"match textResponsePart.text={cited_text!r}; span.start does not index the cited "
            f"text in the generated output"
        )

        if idx == n_citations - 1:
            # The LAST citation's span.end is stretched all the way to len(output.text) even when
            # that swallows the response's own trailing terminal punctuation, which
            # textResponsePart.text never includes. No earlier citation gets this stretch.
            trailer = output_text[start + len(cited_text) : end]
            assert end == len(output_text), (
                f"citation {idx} is the LAST citation but span.end={end} != len(output.text)="
                f"{len(output_text)}"
            )
            assert not any(ch.isalnum() for ch in trailer), (
                f"citation {idx}: the trailing slice output.text[{start + len(cited_text)}:{end}]="
                f"{trailer!r} beyond textResponsePart.text must be punctuation/whitespace filler, "
                f"not additional alphanumeric content the citation never claimed"
            )
        else:
            assert end == start + len(cited_text), (
                f"citation {idx}: span.end={end} != start+len(cited_text)="
                f"{start + len(cited_text)}; a non-terminal citation's span must exactly match "
                f"its cited text with no slack"
            )
        spans.append((start, end, cited_text))

        # The citation points at a source this check actually ingested.
        references = citation["retrievedReferences"]
        assert len(references) >= 1, (
            f"citation {idx} carries zero retrievedReferences, so its 'based on a source in the "
            f"knowledge base' claim is vacuous"
        )
        for ridx, reference in enumerate(references):
            location = reference["location"]
            assert location["type"] == "S3", (
                f"citation {idx} reference {ridx}: the data source is S3, so "
                f"location.type must be 'S3'; got {location['type']!r}"
            )
            uri = location["s3Location"]["uri"]
            assert uri in uris, (
                f"citation {idx} reference {ridx}: location.s3Location.uri={uri!r} is not one of "
                f"the {len(uris)} objects this check ingested {sorted(uris)}; the citation names "
                f"a source that does not exist"
            )

    reference_text = " ".join(
        r["content"]["text"] for c in citations for r in c["retrievedReferences"]
    )
    matched = [t for t in tokens if t in reference_text]
    assert matched, (
        f"no per-run nonce token {sorted(tokens)} appears in any citation's reference content, so "
        f"the citations are not carrying this check's ingested bytes. Reference content was "
        f"{reference_text[:200]!r}"
    )

    # Spans partition the output rather than overlapping.
    ordered = sorted(spans)
    assert ordered == spans, (
        f"citations must be ordered by ascending span.start; got starts "
        f"{[s for s, _e, _t in spans]}"
    )
    for i in range(1, len(ordered)):
        assert ordered[i][0] >= ordered[i - 1][1], (
            f"citation spans overlap: citation {i - 1} covers [{ordered[i - 1][0]}, "
            f"{ordered[i - 1][1]}) and citation {i} starts at {ordered[i][0]}"
        )

    # ---- Terminal read: an independent operation at the destination. The bytes the citations
    # claim to quote are re-fetched from the knowledge base through Retrieve (a different
    # operation than the RetrieveAndGenerate that produced the citations), and the same source
    # URIs must come back. A target that fabricates plausible citations fails here.
    verify = runtime.retrieve(
        knowledgeBaseId=kb_id,
        retrievalQuery={"text": probe},
        retrievalConfiguration={"vectorSearchConfiguration": {"numberOfResults": 5}},
    )["retrievalResults"]
    verify_uris = {r["location"]["s3Location"]["uri"] for r in verify}
    cited_uris = {
        r["location"]["s3Location"]["uri"] for c in citations for r in c["retrievedReferences"]
    }
    assert cited_uris <= verify_uris, (
        f"RetrieveAndGenerate cited source(s) {sorted(cited_uris - verify_uris)} that an "
        f"independent Retrieve for the same query does not return (it returned "
        f"{sorted(verify_uris)}); the citations do not correspond to retrievable content"
    )



def _ingest_two_documents(ctx) -> tuple[set[str], set[str]]:
    """Write two S3 objects, each carrying a distinct per-run nonce token.

    Per-run nonces mean no fixed response can carry the expected values, and they make the
    grounding assertions immune to the model's prior knowledge.
    """
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ragsrc-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 is the only region where CreateBucket must omit LocationConstraint.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _quiet(lambda: s3.delete_bucket(Bucket=bucket)))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK[:250]}]}
    )

    token_a = ctx.unique_name("TOKENALPHA").upper()
    token_b = ctx.unique_name("TOKENBRAVO").upper()
    docs = {
        "project-falcon.txt": (
            f"Project Falcon operations manual. The launch code for Project Falcon is {token_a}. "
            "Only the Falcon launch team may use this code."
        ),
        "project-osprey.txt": (
            f"Project Osprey operations manual. The launch code for Project Osprey is {token_b}. "
            "Only the Osprey launch team may use this code."
        ),
    }
    uris = set()
    for key, body in docs.items():
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=body.encode("utf-8"),
            ContentType="text/plain",
            Tagging=f"sim2real-check={CHECK[:250]}",
        )
        ctx.on_cleanup(lambda k=key: _quiet(lambda: s3.delete_object(Bucket=bucket, Key=k)))
        uris.add(f"s3://{bucket}/{key}")
    return {token_a, token_b}, uris


def _create_s3vectors_knowledge_base(ctx, bucket: str) -> str:
    """Stand up an S3-Vectors-backed knowledge base over `bucket` and ingest it.

    S3 Vectors rather than OpenSearch Serverless.
    """
    ba = ctx.client("bedrock-agent")
    s3v = ctx.client("s3vectors")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket_arn = f"arn:aws:s3:::{bucket}"

    vector_bucket = ctx.unique_name("sim2real-ragvb-").lower()
    s3v.create_vector_bucket(vectorBucketName=vector_bucket)
    ctx.on_cleanup(lambda: _quiet(lambda: s3v.delete_vector_bucket(vectorBucketName=vector_bucket)))
    vector_bucket_arn = s3v.get_vector_bucket(vectorBucketName=vector_bucket)["vectorBucket"][
        "vectorBucketArn"
    ]

    index_name = ctx.unique_name("sim2real-ragvi-").lower()
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
            name=ctx.unique_name("sim2real-ragkb-"),
            roleArn=role_arn,
            knowledgeBaseConfiguration={
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {"embeddingModelArn": embed_arn},
            },
            storageConfiguration={
                "type": "S3_VECTORS",
                "s3VectorsConfiguration": {
                    "vectorBucketArn": vector_bucket_arn,
                    "indexArn": index_arn,
                },
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
        description="knowledge base status ACTIVE (terminal set excludes FAILED, so a failed "
        "create times out loudly rather than being accepted)",
    )

    ds_id = ba.create_data_source(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-ragds-"),
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
        "failed ingestion times out loudly instead of yielding an empty knowledge base)",
    )
    return kb_id


def _create_kb_role(ctx, account_id: str, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ragkbrole-")
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

    policy_name = "sim2real-ragkb-policy"
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
    """IAM is eventually consistent; bedrock.amazonaws.com may not yet be able to assume a
    seconds-old role. Bounded and RAISES on exhaustion."""
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
