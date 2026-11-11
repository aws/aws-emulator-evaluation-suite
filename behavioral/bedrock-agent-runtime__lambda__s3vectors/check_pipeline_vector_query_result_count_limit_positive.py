"""pipeline-vector-query-result-count-limit-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "pipeline-vector-query-result-count-limit-positive"
GROUP = "data-format"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """The pipeline Lambda returns min(topK, stored vectors) citations: 1 for topK=1, every stored vector
    when topK exceeds them, and doc0..doc2 in order for topK=3."""
    bucket_name, index_name = _create_vector_infra(ctx, dimension=4)
    docs = [
        ("doc0", [1.0, 0.0, 0.0, 0.0], "The Eiffel Tower is located in Paris, France. TOKEN-ALPHA-7412."),
        ("doc1", [0.9, 0.1, 0.0, 0.0], "The Louvre Museum is also located in Paris, France. TOKEN-BRAVO-3391."),
        ("doc2", [0.5, 0.5, 0.0, 0.0], "Mount Everest is the tallest mountain above sea level. TOKEN-CHARLIE-5566."),
        ("doc3", [0.0, 0.0, 0.0, 1.0], "The Pacific Ocean is the largest ocean on Earth. TOKEN-DELTA-9087."),
        ("doc4", [0.0, 1.0, 0.0, 0.0], "The Sahara Desert is the largest hot desert on Earth. TOKEN-ECHO-2280."),
    ]
    _put_docs(ctx, bucket_name, index_name, docs)
    total_vectors = len(docs)

    role_arn = _create_lambda_role(
        ctx,
        [
            {"Effect": "Allow", "Action": ["s3vectors:QueryVectors", "s3vectors:GetVectors"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["bedrock:RetrieveAndGenerate", "bedrock:InvokeModel"], "Resource": "*"},
        ],
    )
    function_name = _create_lambda_function(ctx, role_arn, _LAMBDA_CODE)
    query_vector = [1.0, 0.0, 0.0, 0.0]  # exact match to doc0

    # topK below available count: exactly that many citations, nearest match first.
    body_k1 = _invoke_lambda_json_iam_retry(
        ctx,
        function_name,
        {"vectorBucketName": bucket_name, "indexName": index_name, "queryVector": query_vector, "topK": 1},
    )
    assert body_k1["stage"] == "no_generation", f"unexpected stage: {body_k1}"
    assert len(body_k1["citations"]) == 1, f"expected exactly 1 citation for topK=1, got {body_k1['citations']}"
    assert body_k1["citations"][0]["key"] == "doc0", (
        f"expected nearest match doc0 for topK=1, got {body_k1['citations'][0]['key']}"
    )

    # topK exceeds available vectors in the index: capped at total_vectors, not an error
    # and not silently fewer than what's actually there.
    body_k_over = _invoke_lambda_json(
        ctx,
        function_name,
        {
            "vectorBucketName": bucket_name,
            "indexName": index_name,
            "queryVector": query_vector,
            "topK": total_vectors * 2,
        },
    )
    assert body_k_over["stage"] == "no_generation", f"unexpected stage: {body_k_over}"
    assert len(body_k_over["citations"]) == total_vectors, (
        f"expected topK cap at {total_vectors} available vectors, got {len(body_k_over['citations'])}"
    )

    # topK=3, no generation requested: the citation count reaching the pipeline's
    # grounding-data boundary still matches the requested (and available) limit exactly,
    # confirming the limit is enforced end-to-end and not silently truncated or padded.
    body_k3 = _invoke_lambda_json(
        ctx,
        function_name,
        {
            "vectorBucketName": bucket_name,
            "indexName": index_name,
            "queryVector": query_vector,
            "topK": 3,
        },
    )
    assert body_k3["stage"] == "no_generation", f"unexpected stage: {body_k3}"
    assert len(body_k3["citations"]) == 3, f"expected exactly 3 citations for topK=3, got {body_k3['citations']}"
    assert [c["key"] for c in body_k3["citations"]] == ["doc0", "doc1", "doc2"], (
        f"expected nearest-neighbor order [doc0, doc1, doc2], got {[c['key'] for c in body_k3['citations']]}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_LAMBDA_CODE = '''
import json
import boto3
from botocore.exceptions import ClientError

s3v = boto3.client("s3vectors")
bar = boto3.client("bedrock-agent-runtime")


def handler(event, context):
    bucket = event["vectorBucketName"]
    index = event["indexName"]
    query_vector = event["queryVector"]
    top_k = int(event.get("topK", 3))
    model_arn = event.get("modelArn")
    prompt = event.get("prompt", "Summarize the sources.")

    try:
        qresp = s3v.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            queryVector={"float32": query_vector},
            topK=top_k,
            returnDistance=True,
            returnMetadata=True,
        )
    except ClientError as e:
        return {
            "stage": "query_vectors_failed",
            "error_code": e.response["Error"]["Code"],
            "citations": [],
            "answer": None,
        }

    results = qresp.get("vectors", [])
    citations = [
        {
            "key": r["key"],
            "text": (r.get("metadata") or {}).get("text", ""),
            "distance": r.get("distance"),
        }
        for r in results
    ]

    if not citations or not model_arn:
        return {"stage": "no_generation", "citations": citations, "answer": None}

    combined_text = "\\n---\\n".join(c["text"] for c in citations)

    try:
        rag_resp = bar.retrieve_and_generate(
            input={"text": prompt},
            retrieveAndGenerateConfiguration={
                "type": "EXTERNAL_SOURCES",
                "externalSourcesConfiguration": {
                    "modelArn": model_arn,
                    "sources": [
                        {
                            "sourceType": "BYTE_CONTENT",
                            "byteContent": {
                                "identifier": "grounding.txt",
                                "contentType": "text/plain",
                                "data": combined_text.encode("utf-8"),
                            },
                        }
                    ],
                },
            },
        )
    except ClientError as e:
        return {
            "stage": "generate_failed",
            "error_code": e.response["Error"]["Code"],
            "citations": citations,
            "answer": None,
        }

    bedrock_citations = rag_resp.get("citations", [])
    reference_texts = []
    for c in bedrock_citations:
        for ref in c.get("retrievedReferences", []):
            text = (ref.get("content") or {}).get("text")
            if text:
                reference_texts.append(text)

    return {
        "stage": "ok",
        "citations": citations,
        "answer": rag_resp.get("output", {}).get("text"),
        "bedrock_citation_count": len(bedrock_citations),
        "bedrock_reference_texts": reference_texts,
    }
'''


def _create_vector_infra(ctx: Any, dimension: int = 4, distance_metric: str = "cosine"):
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-vb-").lower()
    s3v.create_vector_bucket(vectorBucketName=bucket_name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    index_name = ctx.unique_name("sim2real-idx-").lower()
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=dimension,
        distanceMetric=distance_metric,
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    return bucket_name, index_name


def _put_docs(ctx: Any, bucket_name: str, index_name: str, docs: list[tuple[str, list[float], str]]) -> None:
    s3v = ctx.client("s3vectors")
    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[
            {"key": key, "data": {"float32": vec}, "metadata": {"text": text}}
            for key, vec, text in docs
        ],
    )


def _create_lambda_role(ctx: Any, extra_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rag-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST_POLICY),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            *extra_statements,
        ],
    }
    policy_name = "sim2real-rag-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _zip_lambda_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_function(ctx: Any, role_arn: str, code: str, timeout: int = 60) -> str:
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-rag-fn-")
    zip_bytes = _zip_lambda_code(code)
    last_err = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                MemorySize=256,
                Tags={"sim2real-check": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(4)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=function_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {function_name} Active",
    )
    return function_name


def _invoke_lambda_json(ctx: Any, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised FunctionError={resp['FunctionError']}: {body}")
    return body


def _invoke_lambda_json_iam_retry(
    ctx: Any, function_name: str, payload: dict[str, Any], timeout_s: float = 60.0
) -> dict[str, Any]:
    """Invoke, retrying on AccessDeniedException from s3vectors: the Lambda's execution
    role was just created + granted permissions, and IAM policy attachment does not wait
    for propagation before create_function returns, so the first real call can 401 even
    though the policy is correct."""
    deadline = time.monotonic() + timeout_s
    body = _invoke_lambda_json(ctx, function_name, payload)
    while (
        body.get("stage") == "query_vectors_failed"
        and body.get("error_code") == "AccessDeniedException"
        and time.monotonic() < deadline
    ):
        time.sleep(3.0)
        body = _invoke_lambda_json(ctx, function_name, payload)
    return body


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
