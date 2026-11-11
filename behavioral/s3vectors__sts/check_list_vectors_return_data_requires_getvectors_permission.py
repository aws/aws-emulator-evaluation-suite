"""list-vectors-return-data-requires-getvectors-permission."""

from __future__ import annotations

import json
import struct
import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-vectors-return-data-requires-getvectors-permission"
GROUP = "overly-permissive"
SERVICES = ["s3vectors", "sts"]

_DIMENSION = 4
_VECTORS = {
    "lv-alpha": ([0.5, -0.25, 0.125, 1.0], {"tenant": "tenant-a"}),
    "lv-beta": ([-1.0, 0.75, 0.0625, 0.5], {"tenant": "tenant-b"}),
}
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
    """ListVectors with returnData or returnMetadata also needs s3vectors:GetVectors: a
    ListVectors-only session serves keys only and is refused for each flag; adding GetVectors
    serves both with the data unchanged.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_S3VectorBuckets_ListVectors.html
    """
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3v = ctx.client("s3vectors")

    account = sts.get_caller_identity()["Account"]
    assert account, "STS returned no account id; the check cannot build a trust policy"

    bucket = ctx.unique_name("sim2real-s3v-lvperm-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    index = ctx.unique_name("sim2real-s3v-lvperm-idx-")
    s3v.create_index(
        vectorBucketName=bucket,
        indexName=index,
        dataType="float32",
        dimension=_DIMENSION,
        distanceMetric="euclidean",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=index))

    expected_bits = {
        key: _bits([_as_float32(v) for v in data]) for key, (data, _meta) in _VECTORS.items()
    }
    written_metadata = {key: meta for key, (_data, meta) in _VECTORS.items()}

    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {
                "key": key,
                "data": {"float32": [_as_float32(v) for v in data]},
                "metadata": dict(meta),
            }
            for key, (data, meta) in _VECTORS.items()
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(
            vectorBucketName=bucket, indexName=index, keys=sorted(_VECTORS)
        )
    )

    # Prove the data is readable by a fully-permissioned caller, so a later refusal is not
    # "nothing to return". Newly written vectors are not instantly listable.
    ready = _poll_until(
        lambda: s3v.list_vectors(
            vectorBucketName=bucket, indexName=index, returnData=True, returnMetadata=True
        ),
        lambda r: len(r["vectors"]) == len(_VECTORS),
        timeout_s=60.0,
        interval_s=2.0,
        description=f"all {len(_VECTORS)} vectors became listable to the runner identity",
    )
    runner_view = {v["key"]: v for v in ready["vectors"]}
    assert set(runner_view) == set(_VECTORS), (
        f"runner identity listed {sorted(runner_view)}, expected {sorted(_VECTORS)}"
    )
    for key, item in runner_view.items():
        assert _bits(item["data"]["float32"]) == expected_bits[key], (
            f"{key} float32 bytes changed on the way through ListVectors: expected "
            f"{expected_bits[key]}, got {_bits(item['data']['float32'])}"
        )
        assert item["metadata"] == written_metadata[key], (
            f"{key} metadata changed: expected {written_metadata[key]!r}, got {item['metadata']!r}"
        )

    # ---------- the role: allowed BOTH s3vectors permissions ----------
    role_name = ctx.unique_name("sim2real-s3v-lvperm-role-")
    role_arn = iam.create_role(
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
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(iam, role_name))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-s3v-lvperm-inline",
        PolicyDocument=json.dumps(
            _allow(["s3vectors:ListVectors", "s3vectors:GetVectors"], resource="*")
        ),
    )

    # ---------- reference point: a session with both permissions ----------
    unscoped = _wait_assumable(sts, role_arn, ctx.unique_name("sim2real-sess-full-"))
    _wait_creds_active(ctx, unscoped["Credentials"])
    _poll_allowed(
        lambda: _s3v_for(ctx, unscoped["Credentials"]).list_vectors(
            vectorBucketName=bucket, indexName=index, returnData=True, returnMetadata=True
        ),
        what="returnData+returnMetadata under a session with BOTH permissions",
    )

    # ---------- narrowed session: ListVectors ONLY ----------
    narrow_sess = ctx.unique_name("sim2real-sess-listonly-")
    narrowed = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=narrow_sess,
        Policy=json.dumps(_allow(["s3vectors:ListVectors"], resource="*")),
    )
    assert narrowed["AssumedRoleUser"]["Arn"].endswith(
        f":assumed-role/{role_name}/{narrow_sess}"
    ), (
        "the narrowed session must be the SAME role as the reference session; got "
        f"{narrowed['AssumedRoleUser']['Arn']}"
    )
    _wait_creds_active(ctx, narrowed["Credentials"])
    scoped = _s3v_for(ctx, narrowed["Credentials"])

    # Positive control on the narrowed session: the keys-only listing is permitted.
    keys_only = _poll_allowed(
        lambda: scoped.list_vectors(vectorBucketName=bucket, indexName=index),
        what="keys-only ListVectors under a ListVectors-only session",
    )
    assert {v["key"] for v in keys_only["vectors"]} == set(_VECTORS), (
        f"the ListVectors-only session listed "
        f"{sorted(v['key'] for v in keys_only['vectors'])}, expected {sorted(_VECTORS)}"
    )
    assert all("data" not in v and "metadata" not in v for v in keys_only["vectors"]), (
        "returnData and returnMetadata both default to false, so no element may carry either: "
        f"got {keys_only['vectors']!r}"
    )

    index_arn = f"arn:aws:s3vectors:{ctx.region}:{account}:bucket/{bucket}/index/{index}"
    expected_denial = (
        f"User: {narrowed['AssumedRoleUser']['Arn']} is not authorized to perform: "
        f"s3vectors:GetVectors on resource: {index_arn} because no session policy allows the "
        "s3vectors:GetVectors action"
    )

    # Each flag is asserted separately so a target that gates only one is caught.
    code_data, message_data = _poll_denied(
        lambda: scoped.list_vectors(
            vectorBucketName=bucket, indexName=index, returnData=True
        ),
        _DENIED,
        what="returnData=true without s3vectors:GetVectors",
    )
    assert code_data == _DENIED, (
        f"ListVectors with returnData=true and no s3vectors:GetVectors returned {code_data!r}, "
        f"expected {_DENIED}"
    )
    assert message_data == expected_denial, (
        f"ListVectors returnData=true refusal message: expected {expected_denial!r}, "
        f"got {message_data!r}"
    )

    code_metadata, message_metadata = _poll_denied(
        lambda: scoped.list_vectors(
            vectorBucketName=bucket, indexName=index, returnMetadata=True
        ),
        _DENIED,
        what="returnMetadata=true without s3vectors:GetVectors",
    )
    assert code_metadata == _DENIED, (
        f"ListVectors with returnMetadata=true and no s3vectors:GetVectors returned "
        f"{code_metadata!r}, expected {_DENIED}"
    )
    assert message_metadata == expected_denial, (
        f"ListVectors returnMetadata=true refusal message: expected {expected_denial!r}, "
        f"got {message_metadata!r}"
    )

    # The refusal is about the parameter, not the credential: keys-only still works.
    _poll_allowed(
        lambda: scoped.list_vectors(vectorBucketName=bucket, indexName=index),
        what="keys-only ListVectors on the same session, after the refusals",
    )

    # Adding s3vectors:GetVectors makes the identical refused call succeed with unchanged bytes.
    restored_sess = ctx.unique_name("sim2real-sess-restored-")
    restored = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=restored_sess,
        Policy=json.dumps(
            _allow(["s3vectors:ListVectors", "s3vectors:GetVectors"], resource="*")
        ),
    )
    assert restored["AssumedRoleUser"]["Arn"].endswith(
        f":assumed-role/{role_name}/{restored_sess}"
    ), f"the restored session must be the SAME role; got {restored['AssumedRoleUser']['Arn']}"
    _wait_creds_active(ctx, restored["Credentials"])
    healed = _s3v_for(ctx, restored["Credentials"])

    served = _poll_allowed(
        lambda: healed.list_vectors(
            vectorBucketName=bucket, indexName=index, returnData=True, returnMetadata=True
        ),
        what="returnData+returnMetadata after adding s3vectors:GetVectors to the session policy",
    )
    served_view = {v["key"]: v for v in served["vectors"]}
    assert set(served_view) == set(_VECTORS), (
        f"the restored session listed {sorted(served_view)}, expected {sorted(_VECTORS)}"
    )
    for key, item in served_view.items():
        assert _bits(item["data"]["float32"]) == expected_bits[key], (
            f"{key} float32 bytes differ for the restored session: expected "
            f"{expected_bits[key]}, got {_bits(item['data']['float32'])} -- the permission gate "
            "must decide ACCESS, not content"
        )
        assert item["metadata"] == written_metadata[key], (
            f"{key} metadata differs for the restored session: expected "
            f"{written_metadata[key]!r}, got {item['metadata']!r}"
        )


def _as_float32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def _bits(values) -> list[str]:
    return [struct.pack("<f", float(v)).hex() for v in values]


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


def _refusal(fn, *, what: str) -> tuple[str, str]:
    """The (code, message) refusal of fn(). A call that SUCCEEDS raises: an accepted request is
    never a refusal."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"{what} succeeded, expected a refusal")


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


def _poll_allowed(fn, *, timeout_s: float = 90.0, interval_s: float = 3.0, what: str) -> Any:
    """Poll until fn() SUCCEEDS, returning its value. For POSITIVE controls, where a transient
    InvalidClientTokenId or an unpropagated policy must not read as a denial."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what} became permitted not reached within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _poll_denied(fn, expected: str, *, timeout_s: float = 60.0, what: str) -> tuple[str, str]:
    """Poll until fn() fails with exactly `expected`; a success raises at once. Only ever called
    AFTER a positive control on the SAME session has proven the credential live."""
    return _poll(
        lambda: _refusal(fn, what=what),
        lambda refusal: refusal[0] == expected,
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"{what} became refused with {expected}",
    )


def _wait_creds_active(ctx, credentials: dict) -> None:
    """GetCallerIdentity requires no permissions at all, so it is the one liveness probe safe for
    a session whose permissions are deliberately narrow."""
    probe = _sts_for(ctx, credentials)
    _poll_allowed(
        probe.get_caller_identity,
        timeout_s=90.0,
        interval_s=2.0,
        what="temporary credentials",
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
        lambda: _role_gone(iam, role_name),
        bool,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"role {role_name} disappeared",
    )


def _role_gone(iam, role_name: str) -> bool:
    try:
        iam.get_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
