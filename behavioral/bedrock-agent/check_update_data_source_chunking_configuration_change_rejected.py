"""update-data-source-chunking-configuration-change-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-data-source-chunking-configuration-change-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent"]

_EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
_EMBEDDING_DIMENSION = 1024

# The chunking the data source is CREATED with, and the one an update must not be able to
# reach. Both are valid FIXED_SIZE configurations, so a rejection can only be about
# immutability -- not about the new value being malformed.
_CHUNKING_ORIGINAL = {
    "chunkingStrategy": "FIXED_SIZE",
    "fixedSizeChunkingConfiguration": {"maxTokens": 300, "overlapPercentage": 20},
}
_CHUNKING_ATTEMPTED = {
    "chunkingStrategy": "FIXED_SIZE",
    "fixedSizeChunkingConfiguration": {"maxTokens": 500, "overlapPercentage": 10},
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """chunkingConfiguration is immutable: UpdateDataSource is refused with ValidationException
    whether it sends a different value or omits the field (full-replace), the stored chunking is
    unchanged, and the identical call carrying the ORIGINAL chunking succeeds."""
    bedrock = ctx.client("bedrock-agent")
    account_id, partition = _caller_identity(ctx)
    source_bucket, source_bucket_arn = _create_source_bucket(ctx)
    kb_id = _create_s3_vectors_kb(ctx, account_id, partition, source_bucket_arn)

    ds_name = ctx.unique_name("sim2real-chunkimm-ds-")
    ds_config = {
        "type": "S3",
        "s3Configuration": {"bucketArn": source_bucket_arn},
    }
    ds_id = bedrock.create_data_source(
        knowledgeBaseId=kb_id,
        name=ds_name,
        description="original description",
        dataSourceConfiguration=ds_config,
        vectorIngestionConfiguration={"chunkingConfiguration": _CHUNKING_ORIGINAL},
    )["dataSource"]["dataSourceId"]
    ctx.on_cleanup(
        lambda: _swallow_not_found(
            lambda: bedrock.delete_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)
        )
    )
    _poll_data_source(
        ctx,
        kb_id,
        ds_id,
        timeout_s=120.0,
        reason="a data source connector must reach AVAILABLE before it can be updated",
    )

    stored = _stored_chunking(ctx, kb_id, ds_id)
    assert stored == _CHUNKING_ORIGINAL, (
        f"the data source did not store the chunking it was created with: "
        f"expected {_CHUNKING_ORIGINAL}, got {stored}"
    )

    # ---- Positive control. The SAME UpdateDataSource shape, carrying the ORIGINAL
    # chunking, must succeed -- otherwise "rejects a chunking change" is indistinguishable
    # from "rejects every UpdateDataSource".
    control_description = "positive control: updated with the original chunking"
    bedrock.update_data_source(
        knowledgeBaseId=kb_id,
        dataSourceId=ds_id,
        name=ds_name,
        description=control_description,
        dataSourceConfiguration=ds_config,
        vectorIngestionConfiguration={"chunkingConfiguration": _CHUNKING_ORIGINAL},
    )
    after_control = bedrock.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]
    assert after_control["description"] == control_description, (
        f"positive control UpdateDataSource did not take effect: expected description "
        f"{control_description!r}, got {after_control.get('description')!r}"
    )

    # ---- Negative: break EXACTLY one thing -- the chunking -- and nothing else.
    rejected_description = "this description must never be stored"
    code, message = _refusal(
        lambda: bedrock.update_data_source(
            knowledgeBaseId=kb_id,
            dataSourceId=ds_id,
            name=ds_name,
            description=rejected_description,
            dataSourceConfiguration=ds_config,
            vectorIngestionConfiguration={"chunkingConfiguration": _CHUNKING_ATTEMPTED},
        ),
        what="UpdateDataSource changing chunkingConfiguration after creation",
    )
    # ---- The SPECIFIC error code, and a message tight enough to separate
    # "chunking is immutable" from "your request was malformed".
    assert code == "ValidationException", (
        f"expected ValidationException for a chunkingConfiguration change, got {code!r}: {message!r}"
    )
    assert message == "vectorIngestionConfiguration.chunkingConfiguration cannot be updated once created.", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )
    assert "chunking" in message.lower(), (
        f"the refusal must identify chunking as the immutable field, but the message does not "
        f"mention it: {message!r}"
    )

    # ---- The effect is ABSENT, via an independent read (GetDataSource, not the
    # UpdateDataSource response). Both the chunking AND the description must be unchanged --
    # a target that rejected the chunking but still applied the description is also wrong.
    after_rejection = bedrock.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]
    still_stored = after_rejection["vectorIngestionConfiguration"]["chunkingConfiguration"]
    assert still_stored == _CHUNKING_ORIGINAL, (
        f"the refused UpdateDataSource still changed the stored chunking: "
        f"expected {_CHUNKING_ORIGINAL}, got {still_stored}"
    )
    assert after_rejection["description"] == control_description, (
        f"the refused UpdateDataSource partially applied: description should still be "
        f"{control_description!r}, got {after_rejection.get('description')!r}"
    )

    # ---- Third leg: UpdateDataSource is full-replace for
    # vectorIngestionConfiguration, not a partial patch. Omitting the field entirely does NOT
    # mean "leave chunking untouched" -- it means "chunking defaults to something", and that
    # default differs from the stored FIXED_SIZE/300/20 config, so botocore's own
    # ValidationException fires with the SAME "cannot be updated once created" message as an
    # explicit change: the omission is rejected exactly like the explicit change, not treated
    # as a no-op.
    omitted_description = "this description must never be stored either"
    code, message = _refusal(
        lambda: bedrock.update_data_source(
            knowledgeBaseId=kb_id,
            dataSourceId=ds_id,
            name=ds_name,
            description=omitted_description,
            dataSourceConfiguration=ds_config,
        ),
        what="UpdateDataSource omitting vectorIngestionConfiguration entirely",
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an UpdateDataSource that omits "
        f"vectorIngestionConfiguration entirely, got {code!r}: {message!r}"
    )
    assert message == "vectorIngestionConfiguration.chunkingConfiguration cannot be updated once created.", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )
    assert "chunking" in message.lower(), (
        f"the omission refusal must identify chunking as the immutable field too, but the "
        f"message does not mention it: {message!r}"
    )
    after_omission = bedrock.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]
    assert after_omission["vectorIngestionConfiguration"]["chunkingConfiguration"] == (
        _CHUNKING_ORIGINAL
    ), (
        f"the refused omission-update still changed the stored chunking: expected "
        f"{_CHUNKING_ORIGINAL}, got "
        f"{after_omission['vectorIngestionConfiguration']['chunkingConfiguration']}"
    )
    assert after_omission["description"] == control_description, (
        f"the refused omission-update partially applied: description should still be "
        f"{control_description!r}, got {after_omission.get('description')!r}"
    )

    # ---- Restore the original chunking EXPLICITLY (never by omission -- the
    # leg above just proved omission is itself a rejected "change") and demand that the call
    # succeeds, proving both refusals were about the effective value diverging from what is
    # stored, not about the request shape or about chunkingConfiguration being unconditionally
    # forbidden in an update.
    restored_description = "restored: identical call shape, original chunking"
    bedrock.update_data_source(
        knowledgeBaseId=kb_id,
        dataSourceId=ds_id,
        name=ds_name,
        description=restored_description,
        dataSourceConfiguration=ds_config,
        vectorIngestionConfiguration={"chunkingConfiguration": _CHUNKING_ORIGINAL},
    )
    final = bedrock.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]
    assert final["description"] == restored_description, (
        f"the restored UpdateDataSource did not take effect: expected description "
        f"{restored_description!r}, got {final.get('description')!r}"
    )
    assert final["vectorIngestionConfiguration"]["chunkingConfiguration"] == _CHUNKING_ORIGINAL, (
        f"after restore the chunking must still be the original: expected "
        f"{_CHUNKING_ORIGINAL}, got {final['vectorIngestionConfiguration']['chunkingConfiguration']}"
    )


import json  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402


def _swallow_not_found(fn) -> None:
    """Cleanup helper: a resource already gone is not a teardown failure, anything else is."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _refusal(fn, what: str) -> tuple[str, str]:
    """Return (code, message) for a call that MUST fail.

    RAISES on unexpected success rather than returning a falsy sentinel -- a sentinel would turn
    an over-permissive target's acceptance into a mere code mismatch.
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


def _create_source_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-chunkimm-src-").lower()
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
    """Create an S3 Vectors backed knowledge base.

    S3 Vectors is used rather than OpenSearch Serverless deliberately: an OSS VECTORSEARCH
    collection takes minutes to reach ACTIVE, which no bedrock-agent timeout budget affords.
    """
    s3vectors = ctx.client("s3vectors")
    bedrock = ctx.client("bedrock-agent")

    vector_bucket = ctx.unique_name("sim2real-chunkimm-vec-").lower()
    index_name = ctx.unique_name("sim2real-chunkimm-idx-").lower()
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
        name=ctx.unique_name("sim2real-chunkimm-kb-"),
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
    role_name = ctx.unique_name("sim2real-chunkimm-role-")
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
    """CreateKnowledgeBase, retrying only while the new service role is still propagating.

    Bounded by a deadline and RAISES on expiry -- never a bare sleep.
    """
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
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ValidationException"):
                raise
            last_exc = exc
            time.sleep(5)  # bounded: inside a deadline-guarded IAM-propagation retry
    raise AssertionError(
        f"CreateKnowledgeBase never succeeded within {timeout_s}s of role-propagation retries; "
        f"last error={last_exc}"
    )


def _poll_data_source(ctx, kb_id: str, ds_id: str, timeout_s: float, reason: str) -> dict:
    """Bounded poll for AVAILABLE. RAISES on timeout and on FAILED."""
    bedrock = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = bedrock.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]
        if last["status"] == "FAILED":
            raise AssertionError(
                f"data source {ds_id} reached FAILED while waiting ({reason}): {last}"
            )
        if last["status"] == "AVAILABLE":
            return last
        time.sleep(5)
    raise AssertionError(
        f"data source {ds_id} never reached AVAILABLE within {timeout_s}s ({reason}); "
        f"last status={None if last is None else last.get('status')!r}"
    )


def _stored_chunking(ctx, kb_id: str, ds_id: str) -> dict:
    ds = ctx.client("bedrock-agent").get_data_source(
        knowledgeBaseId=kb_id, dataSourceId=ds_id
    )["dataSource"]
    # Hard-subscripted deliberately: a data source created WITH a chunkingConfiguration must
    # report one back, and a missing key is a failure to surface loudly, not to default away.
    return ds["vectorIngestionConfiguration"]["chunkingConfiguration"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
