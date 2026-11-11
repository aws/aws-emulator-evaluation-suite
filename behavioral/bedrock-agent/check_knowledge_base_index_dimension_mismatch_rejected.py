"""knowledge-base-index-dimension-mismatch-rejected."""

# CreateKnowledgeBase refuses a dimension-mismatched S3 Vectors binding synchronously with
# ValidationException. Bedrock validates the binding with a probe query against the index, so
# the message wraps the index's own "Query vector contains invalid values or is invalid for this
# index" under "storage configuration provided is invalid" rather than naming "dimension".
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "knowledge-base-index-dimension-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent"]

_EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"

# Two dimensions Titan embed text v2 supports, and which an S3 Vectors index accepts. The KB is
# always configured for _CONFIGURED_DIMENSION; only the index it is pointed at changes.
_CONFIGURED_DIMENSION = 1024
_MISMATCHED_DIMENSION = 512


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateKnowledgeBase refuses to bind a vector index whose dimension disagrees with the
    embedding model's configured output dimension, while the identical call against a
    correctly-dimensioned index in the same vector bucket succeeds."""
    bedrock = ctx.client("bedrock-agent")
    s3vectors = ctx.client("s3vectors")
    account_id, partition = _caller_identity(ctx)
    # A single run-scoped name stem, computed ONCE. Every knowledge base this check creates is
    # named from it, so the listing assertions below are scoped to THIS run and cannot be
    # perturbed by a concurrent run of this same check.
    kb_name_stem = ctx.unique_name("sim2real-kbdim-kb-")

    vector_bucket = ctx.unique_name("sim2real-kbdim-vec-").lower()
    s3vectors.create_vector_bucket(vectorBucketName=vector_bucket)
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: s3vectors.delete_vector_bucket(vectorBucketName=vector_bucket)
        )
    )
    bucket_arn = f"arn:{partition}:s3vectors:{ctx.region}:{account_id}:bucket/{vector_bucket}"

    matching_index = _create_index(ctx, vector_bucket, "match", _CONFIGURED_DIMENSION)
    mismatched_index = _create_index(ctx, vector_bucket, "mismatch", _MISMATCHED_DIMENSION)

    # The mismatch is DERIVED from what the store itself reports, not asserted as a literal.
    matching_dim = _index_dimension(ctx, vector_bucket, matching_index)
    mismatched_dim = _index_dimension(ctx, vector_bucket, mismatched_index)
    assert matching_dim == _CONFIGURED_DIMENSION, (
        f"the control index must report the dimension it was created with: expected "
        f"{_CONFIGURED_DIMENSION}, got {matching_dim}"
    )
    assert mismatched_dim != _CONFIGURED_DIMENSION, (
        f"the subject index must genuinely disagree with the embedding configuration, otherwise "
        f"there is no mismatch to reject: index dimension {mismatched_dim} vs configured "
        f"{_CONFIGURED_DIMENSION}"
    )

    embedding_model_arn = (
        f"arn:{partition}:bedrock:{ctx.region}::foundation-model/{_EMBEDDING_MODEL}"
    )
    role_arn = _create_kb_role(
        ctx, account_id, partition, bucket_arn, embedding_model_arn
    )

    def _create_kb_against(index_name: str, name_suffix: str):
        """The one call shape under test. ONLY indexArn varies between the control and the
        mismatch leg; name_suffix exists only so the restore leg (which points at the SAME
        matching_index as the control) does not collide with the still-live control KB --
        CreateKnowledgeBase's own name uniqueness is account-wide, not a signal under test."""
        return bedrock.create_knowledge_base(
            name=f"{kb_name_stem}-{index_name[-8:]}-{name_suffix}",
            roleArn=role_arn,
            knowledgeBaseConfiguration={
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {
                    "embeddingModelArn": embedding_model_arn,
                    "embeddingModelConfiguration": {
                        "bedrockEmbeddingModelConfiguration": {
                            "dimensions": _CONFIGURED_DIMENSION
                        }
                    },
                },
            },
            storageConfiguration={
                "type": "S3_VECTORS",
                "s3VectorsConfiguration": {
                    "vectorBucketArn": bucket_arn,
                    "indexArn": f"{bucket_arn}/index/{index_name}",
                },
            },
            tags={"sim2real-check": CHECK},
        )["knowledgeBase"]["knowledgeBaseId"]

    # ---- Positive control. The identical shape against the matching index works.
    # Without it, "rejects a dimension mismatch" is indistinguishable from "rejects every
    # CreateKnowledgeBase" -- or from an account with no embedding-model access at all.
    control_kb = _with_propagation_retry(ctx, lambda: _create_kb_against(matching_index, "control"))
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: bedrock.delete_knowledge_base(knowledgeBaseId=control_kb)
        )
    )
    _poll_kb_active(ctx, control_kb, 180.0, "the positive-control knowledge base must become ACTIVE")
    mine_after_control = _my_knowledge_bases(ctx, kb_name_stem)
    assert mine_after_control == {control_kb}, (
        f"exactly the positive-control knowledge base must exist under this check's name prefix: "
        f"expected {{{control_kb}}}, got {sorted(mine_after_control)}. If this fails with extra "
        f"ids, a previous run leaked and the effect-absent assertion below cannot be trusted."
    )

    # ---- Change EXACTLY one thing -- the index dimension -- and demand the
    # specific refusal.
    code, message = _refusal(
        lambda: _create_kb_against(mismatched_index, "mismatch"),
        what=(
            f"CreateKnowledgeBase binding a {mismatched_dim}-dimension index while the embedding "
            f"model is configured for {_CONFIGURED_DIMENSION}"
        ),
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an index/embedding dimension mismatch "
        f"({mismatched_dim} vs {_CONFIGURED_DIMENSION}), got {code!r}: {message!r}"
    )
    # The message never contains "dimension": CreateKnowledgeBase probes the bound index and forwards
    # the S3 Vectors refusal verbatim, including its per-request Request ID, which is matched by
    # pattern inside the otherwise exact message.
    prefix = (
        "The knowledge base storage configuration provided is invalid... Query vector contains "
        "invalid values or is invalid for this index (Service: S3Vectors, Status Code: 400, "
        "Request ID: "
    )
    suffix = ") (SDK Attempt Count: 1)"
    assert message.startswith(prefix) and message.endswith(suffix), f"unexpected refusal message: {message!r}"
    expected = re.escape(prefix) + r"[A-Za-z0-9-]+" + re.escape(suffix)
    assert re.fullmatch(expected, message), f"unexpected refusal message: {message!r}"
    lowered = message.lower()
    assert "storage configuration" in lowered, (
        f"the refusal must identify the knowledge base's storage configuration (the index "
        f"binding) as the problem, so it can be told apart from a generic bad request; message "
        f"was {message!r}"
    )
    assert "s3vectors" in lowered and "query vector" in lowered, (
        f"the refusal must forward the underlying S3 Vectors rejection of the probe query "
        f"against the mismatched index, which is how CreateKnowledgeBase actually detects the "
        f"mismatch; message was {message!r}"
    )

    # ---- The effect is ABSENT, via an independent read (ListKnowledgeBases, not the
    # create's own response). Exactly one knowledge base may exist for this check.
    mine_after_refusal = _my_knowledge_bases(ctx, kb_name_stem)
    assert mine_after_refusal == mine_after_control, (
        f"the refused CreateKnowledgeBase must leave no record behind: this check's knowledge "
        f"bases went from {sorted(mine_after_control)} to {sorted(mine_after_refusal)} "
        f"(added {sorted(mine_after_refusal - mine_after_control)})"
    )

    # ---- Restore -- point the IDENTICAL call shape back at the correctly
    # dimensioned index and demand it succeed. The index dimension is immutable, so the restore
    # is achieved by substituting the index, which is the single field that was broken.
    restored_kb = _with_propagation_retry(ctx, lambda: _create_kb_against(matching_index, "restore"))
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: bedrock.delete_knowledge_base(knowledgeBaseId=restored_kb)
        )
    )
    _poll_kb_active(ctx, restored_kb, 180.0, "the restored knowledge base must become ACTIVE")
    mine_final = _my_knowledge_bases(ctx, kb_name_stem)
    assert mine_final == {control_kb, restored_kb}, (
        f"the restore leg must add exactly one knowledge base: expected "
        f"{sorted({control_kb, restored_kb})}, got {sorted(mine_final)}"
    )

    # The stored configuration must reflect what was asked for, so the success is not a success
    # at some other dimension the service silently substituted.
    stored = bedrock.get_knowledge_base(knowledgeBaseId=restored_kb)["knowledgeBase"]
    configured = stored["knowledgeBaseConfiguration"]["vectorKnowledgeBaseConfiguration"][
        "embeddingModelConfiguration"
    ]["bedrockEmbeddingModelConfiguration"]["dimensions"]
    assert configured == _CONFIGURED_DIMENSION, (
        f"the accepted knowledge base must store the embedding dimension that was requested: "
        f"expected {_CONFIGURED_DIMENSION}, got {configured}"
    )
    bound_index = stored["storageConfiguration"]["s3VectorsConfiguration"]["indexArn"]
    assert bound_index.endswith(f"/index/{matching_index}"), (
        f"the accepted knowledge base must be bound to the matching index: expected an ARN ending "
        f"/index/{matching_index}, got {bound_index}"
    )


import json  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402


def _swallow_not_found(fn) -> None:
    """Cleanup helper: a resource already gone is not a teardown failure, anything else is."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NotFoundException"):
            raise


def _refusal(fn, what: str) -> tuple[str, str]:
    """Return (code, message) for a call that MUST fail.

    RAISES on unexpected success rather than returning a falsy sentinel -- a sentinel would turn an
    over-permissive target's acceptance into a mere code mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected {what} to be refused, but it succeeded")


def _caller_identity(ctx) -> tuple[str, str]:
    identity = ctx.client("sts").get_caller_identity()
    return identity["Account"], identity["Arn"].split(":")[1]


def _create_index(ctx, vector_bucket: str, label: str, dimension: int) -> str:
    s3vectors = ctx.client("s3vectors")
    index_name = ctx.unique_name(f"sim2real-kbdim-{label}-").lower()
    s3vectors.create_index(
        vectorBucketName=vector_bucket,
        indexName=index_name,
        dataType="float32",
        dimension=dimension,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: s3vectors.delete_index(vectorBucketName=vector_bucket, indexName=index_name)
        )
    )
    return index_name


def _index_dimension(ctx, vector_bucket: str, index_name: str) -> int:
    """The index's own reported dimension. Hard-subscripted: a vector index must report one."""
    return ctx.client("s3vectors").get_index(
        vectorBucketName=vector_bucket, indexName=index_name
    )["index"]["dimension"]


def _create_kb_role(ctx, account_id, partition, bucket_arn, embedding_model_arn) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-kbdim-role-")
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
                        "Resource": [bucket_arn, f"{bucket_arn}/index/*"],
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


def _with_propagation_retry(ctx, fn, timeout_s: float = 120.0):
    """Run fn, retrying ONLY IAM-propagation failures. RAISES on expiry or on any other error.

    Measured on real AWS: a role used immediately after creation makes CreateKnowledgeBase
    report the propagation race as ValidationException("...was unable to assume the given
    role..."), not AccessDeniedException -- botocore's own error classification for this
    specific Bedrock check is by message, not code. The dimension-mismatch ValidationException
    this check's subject raises carries a wholly different message ("dimension") and is never
    routed through this helper in the first place (see `_refusal` call site above), so widening
    the match here cannot hide the signal under test.
    """
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            is_propagation_lag = err["Code"] == "AccessDeniedException" or (
                err["Code"] == "ValidationException"
                and "unable to assume the given role" in err.get("Message", "")
            )
            if not is_propagation_lag:
                raise
            last_exc = exc
            time.sleep(5)  # bounded: inside a deadline-guarded IAM-propagation retry
    raise AssertionError(
        f"the call never succeeded within {timeout_s}s of role-propagation retries; "
        f"last error={last_exc}"
    )


def _poll_kb_active(ctx, kb_id: str, timeout_s: float, reason: str) -> None:
    """Bounded poll for ACTIVE. RAISES on timeout and on FAILED.

    FAILED is excluded from the terminal set deliberately: if real AWS accepts the mismatched
    binding and parks it in FAILED rather than refusing, that must surface as a loud,
    named failure rather than as convergence.
    """
    bedrock = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        kb = bedrock.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
        last = kb["status"]
        if last == "FAILED":
            raise AssertionError(
                f"knowledge base {kb_id} reached FAILED instead of ACTIVE ({reason}): "
                f"{kb.get('failureReasons')}"
            )
        if last == "ACTIVE":
            return
        time.sleep(5)
    raise AssertionError(
        f"knowledge base {kb_id} never reached ACTIVE within {timeout_s}s ({reason}); "
        f"last status={last!r}"
    )


def _my_knowledge_bases(ctx, stem: str) -> set:
    """Knowledge base ids created BY THIS CHECK, identified by its own name stem (paginated).

    Scoped to this check's own resources rather than the whole account: an account-wide count
    would flake whenever a concurrent check creates a knowledge base, and cleanup and
    assertions alike must be limited to what this check created.
    """
    bedrock = ctx.client("bedrock-agent")
    found = set()
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = bedrock.list_knowledge_bases(**kwargs)
        for summary in resp["knowledgeBaseSummaries"]:
            if summary["name"].startswith(stem):
                found.add(summary["knowledgeBaseId"])
        token = resp.get("nextToken")
        if not token:
            return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
