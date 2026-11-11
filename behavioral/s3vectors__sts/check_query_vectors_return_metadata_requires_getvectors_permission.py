"""query-vectors-return-metadata-requires-getvectors-permission."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "query-vectors-return-metadata-requires-getvectors-permission"
GROUP = "overly-permissive"
SERVICES = ["s3vectors", "sts"]

_DIMENSION = 3
_VECTORS = {
    "qv-alpha": ([1.0, 0.0, 0.0], {"tenant": "tenant-a", "label": "alpha"}),
    "qv-beta": ([0.0, 1.0, 0.0], {"tenant": "tenant-b", "label": "beta"}),
}
_QUERY = [1.0, 0.1, 0.0]
_DENIED = "AccessDeniedException"


@tags(
    "axis:rejection",
    "cap:c2",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """QueryVectors with returnMetadata or a metadata filter also needs s3vectors:GetVectors: a
    QueryVectors-only session serves keys only and is refused for each; adding GetVectors
    serves both.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_S3VectorBuckets_QueryVectors.html
    """
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3v = ctx.client("s3vectors")

    identity = sts.get_caller_identity()
    account = identity["Account"]
    assert account, "STS returned no account id; the check cannot build a trust policy"

    bucket = ctx.unique_name("sim2real-s3v-xsvc-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    index = ctx.unique_name("sim2real-s3v-xsvc-idx-")
    s3v.create_index(
        vectorBucketName=bucket,
        indexName=index,
        dataType="float32",
        dimension=_DIMENSION,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=index))

    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {"key": key, "data": {"float32": list(data)}, "metadata": dict(meta)}
            for key, (data, meta) in _VECTORS.items()
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(
            vectorBucketName=bucket, indexName=index, keys=sorted(_VECTORS)
        )
    )
    index_arn = s3v.get_index(vectorBucketName=bucket, indexName=index)["index"]["indexArn"]
    assert index_arn.endswith(f"/index/{index}"), (
        f"GetIndex returned indexArn {index_arn!r}, which does not name index {index!r}"
    )

    # Prove the metadata is readable by a fully-permissioned caller, so a later refusal is not
    # "no metadata to return".
    ready = _poll_until(
        lambda: s3v.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            topK=len(_VECTORS),
            queryVector={"float32": list(_QUERY)},
            returnMetadata=True,
        ),
        lambda r: len(r["vectors"]) == len(_VECTORS),
        timeout_s=60.0,
        interval_s=2.0,
        description=f"all {len(_VECTORS)} vectors became queryable to the runner identity",
    )
    runner_metadata = {v["key"]: v["metadata"] for v in ready["vectors"]}
    written_metadata = {key: meta for key, (_data, meta) in _VECTORS.items()}
    assert runner_metadata == written_metadata, (
        f"runner identity read back metadata {runner_metadata!r}, expected {written_metadata!r}"
    )

    # ---------- the role: allowed BOTH s3vectors permissions ----------
    role_name = ctx.unique_name("sim2real-s3v-xsvc-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["Role"]
    ctx.on_cleanup(lambda: _drop_role(iam, role_name))
    role_arn = role["Arn"]

    policy_name = "sim2real-s3v-xsvc-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            _allow(["s3vectors:QueryVectors", "s3vectors:GetVectors"], resource="*")
        ),
    )

    # ---------- unscoped session: the reference point ----------
    unscoped = _wait_assumable(sts, role_arn, ctx.unique_name("sim2real-sess-full-"))
    full = _s3v_for(ctx, unscoped["Credentials"])
    _wait_creds_active(ctx, unscoped["Credentials"])
    _poll_allowed(
        lambda: full.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            topK=len(_VECTORS),
            queryVector={"float32": list(_QUERY)},
            returnMetadata=True,
        ),
        what="returnMetadata=true under a session with BOTH permissions",
    )

    # ---------- narrowed session: QueryVectors ONLY ----------
    narrow_sess = ctx.unique_name("sim2real-sess-queryonly-")
    narrowed = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=narrow_sess,
        Policy=json.dumps(_allow(["s3vectors:QueryVectors"], resource="*")),
    )
    assert narrowed["AssumedRoleUser"]["Arn"].endswith(
        f":assumed-role/{role_name}/{narrow_sess}"
    ), (
        "the narrowed session must be the SAME role as the unscoped one, or the comparison is "
        f"between two different principals; got {narrowed['AssumedRoleUser']['Arn']}"
    )
    _wait_creds_active(ctx, narrowed["Credentials"])
    scoped = _s3v_for(ctx, narrowed["Credentials"])

    # Positive control on the narrowed session, so a refusal below is not "refuses every query".
    keys_only = _poll_allowed(
        lambda: scoped.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            topK=len(_VECTORS),
            queryVector={"float32": list(_QUERY)},
            returnDistance=True,
        ),
        what="keys-only QueryVectors under a QueryVectors-only session",
    )
    assert {v["key"] for v in keys_only["vectors"]} == set(_VECTORS), (
        f"the QueryVectors-only session returned keys "
        f"{sorted(v['key'] for v in keys_only['vectors'])}, expected {sorted(_VECTORS)}"
    )
    assert all("metadata" not in v for v in keys_only["vectors"]), (
        "returnMetadata defaults to false, so no element may carry metadata: got "
        f"{keys_only['vectors']!r}"
    )

    # Change exactly one parameter: returnMetadata.
    code_metadata, message_metadata = _poll_denied(
        lambda: scoped.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            topK=len(_VECTORS),
            queryVector={"float32": list(_QUERY)},
            returnMetadata=True,
        ),
        _DENIED,
        what="returnMetadata=true without s3vectors:GetVectors",
    )
    assert code_metadata == _DENIED, (
        f"QueryVectors with returnMetadata=true and no s3vectors:GetVectors returned "
        f"{code_metadata!r}, expected {_DENIED}"
    )
    narrowed_arn = narrowed["AssumedRoleUser"]["Arn"]
    expected_denial = (
        f"User: {narrowed_arn} is not authorized to perform: s3vectors:GetVectors on resource: "
        f"{index_arn} because no session policy allows the s3vectors:GetVectors action"
    )
    assert message_metadata == expected_denial, (
        f"QueryVectors with returnMetadata=true was refused with message {message_metadata!r}, "
        f"expected {expected_denial!r}"
    )

    # A metadata filter alone, with returnMetadata left at its default of false.
    code_filter, message_filter = _poll_denied(
        lambda: scoped.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            topK=len(_VECTORS),
            queryVector={"float32": list(_QUERY)},
            filter={"tenant": "tenant-b"},
        ),
        _DENIED,
        what="a metadata filter without s3vectors:GetVectors",
    )
    assert code_filter == _DENIED, (
        f"QueryVectors with a filter and no s3vectors:GetVectors returned {code_filter!r}, "
        f"expected {_DENIED}"
    )
    assert message_filter == expected_denial, (
        f"QueryVectors with a filter was refused with message {message_filter!r}, "
        f"expected {expected_denial!r}"
    )

    # The refusals are about the parameter, not the credential: keys-only still works.
    _poll_allowed(
        lambda: scoped.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            topK=len(_VECTORS),
            queryVector={"float32": list(_QUERY)},
        ),
        what="keys-only QueryVectors on the same session, after the refusals",
    )

    # Adding s3vectors:GetVectors makes the identical refused call succeed with the metadata.
    restored_sess = ctx.unique_name("sim2real-sess-restored-")
    restored = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=restored_sess,
        Policy=json.dumps(
            _allow(["s3vectors:QueryVectors", "s3vectors:GetVectors"], resource="*")
        ),
    )
    assert restored["AssumedRoleUser"]["Arn"].endswith(
        f":assumed-role/{role_name}/{restored_sess}"
    ), (
        "the restored session must be the SAME role; got "
        f"{restored['AssumedRoleUser']['Arn']}"
    )
    _wait_creds_active(ctx, restored["Credentials"])
    healed = _s3v_for(ctx, restored["Credentials"])
    served = _poll_allowed(
        lambda: healed.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            topK=len(_VECTORS),
            queryVector={"float32": list(_QUERY)},
            returnMetadata=True,
        ),
        what="returnMetadata=true after adding s3vectors:GetVectors to the session policy",
    )
    served_metadata = {v["key"]: v["metadata"] for v in served["vectors"]}
    assert served_metadata == runner_metadata, (
        f"the restored session read back metadata {served_metadata!r}, expected the same "
        f"{runner_metadata!r} the runner identity sees -- the permission gate must decide "
        "ACCESS, not content"
    )

    # The filtered query is served too and returns only the matching vector.
    filtered = _poll_allowed(
        lambda: healed.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            topK=len(_VECTORS),
            queryVector={"float32": list(_QUERY)},
            filter={"tenant": "tenant-b"},
            returnMetadata=True,
        ),
        what="a metadata filter after adding s3vectors:GetVectors",
    )
    assert {v["key"] for v in filtered["vectors"]} == {"qv-beta"}, (
        f"the restored filtered query returned "
        f"{sorted(v['key'] for v in filtered['vectors'])}, expected ['qv-beta'] -- the query "
        "vector is nearest to qv-alpha, so only the filter can produce this result"
    )


def _allow(actions: list[str], *, resource: str = "*") -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}],
    }


def _s3v_for(ctx, credentials: dict):
    """An s3vectors client signing with the assumed-role session, keeping the target's endpoint."""
    return ctx.client(
        "s3vectors",
        creds={
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretAccessKey"],
            "aws_session_token": credentials["SessionToken"],
        },
    )


def _sts_for(ctx, credentials: dict):
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretAccessKey"],
            "aws_session_token": credentials["SessionToken"],
        },
    )


def _attempt(fn) -> tuple[bool, Any]:
    """(True, result) when fn() succeeds, (False, the Error dict) when it raises ClientError."""
    from botocore.exceptions import ClientError

    try:
        return True, fn()
    except ClientError as exc:
        return False, exc.response["Error"]


def _poll(probe, predicate, *, timeout_s: float, interval_s: float, description: str) -> Any:
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


_poll_until = _poll


def _poll_allowed(fn, *, timeout_s: float = 90.0, what: str) -> Any:
    """Poll until fn() SUCCEEDS, returning its value. For POSITIVE controls, where a transient
    InvalidClientTokenId or an unpropagated policy must not read as a denial."""
    ok, value = _poll(
        lambda: _attempt(fn),
        lambda r: r[0],
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"{what} became permitted",
    )
    return value


def _poll_denied(fn, expected: str, *, timeout_s: float = 60.0, what: str) -> tuple[str, str]:
    """Poll until fn() fails with exactly `expected`; return the refusal's (code, message).
    Called only after a positive control on the same session, so a short deadline is safe."""
    _ok, err = _poll(
        lambda: _attempt(fn),
        lambda r: not r[0] and r[1].get("Code") == expected,
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"{what} became refused with {expected}",
    )
    return err.get("Code"), err.get("Message")


def _wait_creds_active(ctx, credentials: dict) -> None:
    """GetCallerIdentity requires no permissions at all, so it is the one liveness probe safe for
    a session whose permissions are deliberately narrow."""
    probe = _sts_for(ctx, credentials)
    _poll(
        lambda: _attempt(probe.get_caller_identity),
        lambda r: r[0],
        timeout_s=90.0,
        interval_s=2.0,
        description="temporary credentials became active",
    )


def _try_assume(client, role_arn: str, session_name: str, **kw) -> Any:
    from botocore.exceptions import ClientError

    try:
        return client.assume_role(RoleArn=role_arn, RoleSessionName=session_name, **kw)
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _wait_assumable(client, role_arn: str, session_name: str, **kw) -> Any:
    """Poll AssumeRole until the new role's trust policy has propagated (it fails for seconds)."""
    return _poll(
        lambda: _try_assume(client, role_arn, session_name, **kw),
        lambda r: isinstance(r, dict),
        timeout_s=180.0,
        interval_s=3.0,
        description=f"role {role_arn} became assumable",
    )


def _drop_role(iam, role_name: str) -> None:
    """Remove the role's policies (they block delete_role), delete it, and wait until it is gone."""
    for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
        for pol in page["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
        for name in page["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    iam.delete_role(RoleName=role_name)
    _poll(
        lambda: _attempt(lambda: iam.get_role(RoleName=role_name)),
        lambda r: not r[0] and r[1].get("Code") == "NoSuchEntity",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"role {role_name} disappeared",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
