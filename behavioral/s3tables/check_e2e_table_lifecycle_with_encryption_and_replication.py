"""e2e-table-lifecycle-with-encryption-and-replication."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-table-lifecycle-with-encryption-and-replication"
GROUP = "e2e"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table in an encrypted bucket replicates to COMPLETED (not merely a destination entry),
    and deleting replication, the table, the namespace and the bucket is each proven by an
    independent read returning NotFoundException."""
    s3tables = ctx.client("s3tables")
    iam = ctx.client("iam")

    src_arn = _create_table_bucket(ctx, "src")
    dst_arn = _create_table_bucket(ctx, "dst")

    s3tables.put_table_bucket_encryption(
        tableBucketARN=src_arn, encryptionConfiguration={"sseAlgorithm": "AES256"}
    )
    ctx.on_cleanup(lambda: _delete_encryption_if_present(s3tables, src_arn))

    namespace_name = ctx.unique_name("ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=src_arn, namespace=[namespace_name])
    ctx.on_cleanup(lambda: _delete_namespace_if_present(s3tables, src_arn, namespace_name))
    table_name = ctx.unique_name("tbl_").replace("-", "_")
    created = s3tables.create_table(
        tableBucketARN=src_arn,
        namespace=namespace_name,
        name=table_name,
        format="ICEBERG",
        tags={"sim2real-check": CHECK},
    )
    table_arn = created["tableARN"]
    ctx.on_cleanup(
        lambda: _delete_table_if_present(s3tables, src_arn, namespace_name, table_name)
    )

    role_arn = _create_replication_role(ctx, iam, [src_arn, dst_arn])
    ctx.on_cleanup(lambda: _delete_bucket_replication_if_present(s3tables, src_arn))

    def _delete_replica() -> None:
        # Replication writes the same namespace and table into the destination bucket, and
        # DeleteTableBucket refuses a bucket that is not empty.
        _delete_table_if_present(s3tables, dst_arn, namespace_name, table_name)
        _delete_namespace_if_present(s3tables, dst_arn, namespace_name)

    ctx.on_cleanup(_delete_replica)

    status = _replicate_until_completed(
        s3tables, src_arn, role_arn, dst_arn, table_arn, timeout_s=220.0
    )
    assert status["sourceTableArn"] == table_arn, (
        f"expected sourceTableArn={table_arn!r}, got {status.get('sourceTableArn')!r}"
    )
    dests = status["destinations"]
    assert len(dests) == 1, f"expected exactly 1 destination, got {len(dests)}: {dests!r}"
    dest = dests[0]
    assert dest["destinationTableBucketArn"] == dst_arn, (
        f"expected destination bucket {dst_arn!r}, got "
        f"{dest.get('destinationTableBucketArn')!r}"
    )
    assert str(dest.get("replicationStatus", "")).upper() == "COMPLETED", (
        f"expected replication to reach COMPLETED, got "
        f"status={dest.get('replicationStatus')!r} failureMessage={dest.get('failureMessage')!r}"
    )

    # Delete in the body so each deletion's consequence, an independent read no longer
    # finding the thing, is asserted.
    replication_version_token = _current_replication_version_token(s3tables, src_arn)
    s3tables.delete_table_bucket_replication(
        tableBucketARN=src_arn, versionToken=replication_version_token
    )
    assert _error_of(
        lambda: s3tables.get_table_bucket_replication(tableBucketARN=src_arn)
    ) == ("NotFoundException", "The specified replication configuration does not exist."), (
        "expected replication config to be gone after delete"
    )

    s3tables.delete_table(tableBucketARN=src_arn, namespace=namespace_name, name=table_name)
    assert (
        _error_of(
            lambda: s3tables.get_table(
                tableBucketARN=src_arn, namespace=namespace_name, name=table_name
            )
        )
        == ("NotFoundException", "The specified table does not exist.")
    ), f"expected table {table_name!r} to be gone after delete"

    s3tables.delete_namespace(tableBucketARN=src_arn, namespace=namespace_name)
    assert (
        _error_of(
            lambda: s3tables.get_namespace(tableBucketARN=src_arn, namespace=namespace_name)
        )
        == ("NotFoundException", "The specified namespace does not exist.")
    ), f"expected namespace {namespace_name!r} to be gone after delete"

    s3tables.delete_table_bucket(tableBucketARN=src_arn)
    assert (
        _error_of(lambda: s3tables.get_table_bucket(tableBucketARN=src_arn))
        == ("NotFoundException", "The specified bucket does not exist.")
    ), f"expected table bucket {src_arn!r} to be gone after delete"


# ===== helpers =====


def _create_table_bucket(ctx: Any, tag: str) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{tag}-")
    arn = s3tables.create_table_bucket(name=name, tags={"sim2real-check": CHECK})["arn"]
    ctx.on_cleanup(lambda: _delete_bucket_if_present(s3tables, arn))
    return arn


def _delete_encryption_if_present(s3tables: Any, bucket_arn: str) -> None:
    try:
        s3tables.delete_table_bucket_encryption(tableBucketARN=bucket_arn)
    except Exception as exc:  # noqa: BLE001
        code = _error_code(exc)
        if code != "NotFoundException":
            raise


def _delete_bucket_replication_if_present(s3tables: Any, bucket_arn: str) -> None:
    try:
        version_token = _current_replication_version_token(s3tables, bucket_arn)
        if version_token is None:
            return
        s3tables.delete_table_bucket_replication(
            tableBucketARN=bucket_arn, versionToken=version_token
        )
    except Exception as exc:  # noqa: BLE001
        code = _error_code(exc)
        if code != "NotFoundException":
            raise


def _delete_table_if_present(s3tables: Any, bucket_arn: str, namespace: str, name: str) -> None:
    try:
        s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    except Exception as exc:  # noqa: BLE001
        if _error_code(exc) != "NotFoundException":
            raise


def _delete_namespace_if_present(s3tables: Any, bucket_arn: str, namespace: str) -> None:
    try:
        s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
    except Exception as exc:  # noqa: BLE001
        if _error_code(exc) != "NotFoundException":
            raise


def _delete_bucket_if_present(s3tables: Any, bucket_arn: str) -> None:
    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except Exception as exc:  # noqa: BLE001
        if _error_code(exc) != "NotFoundException":
            raise


def _error_code(exc: Any) -> str | None:
    resp = getattr(exc, "response", None)
    if not resp:
        return None
    return resp.get("Error", {}).get("Code")


def _error_of(fn: Any) -> tuple[str, str]:
    """Call fn(); return the ClientError's (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_replication_role(ctx: Any, iam: Any, resource_arns: list[str]) -> str:
    role_name = ctx.unique_name("sim2real-s3t-repl-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "replication.s3tables.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    perm_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3tables:*"],
                "Resource": [f"{arn}*" for arn in resource_arns] + resource_arns,
            }
        ],
    }
    policy_name = "sim2real-s3t-repl-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(perm_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _put_bucket_replication_with_retry(
    s3tables: Any, src_arn: str, role_arn: str, dst_arn: str, timeout_s: float
) -> None:
    """IAM roles are eventually consistent; S3 Tables may reject the role until it
    propagates, so retry PutTableBucketReplication on AccessDenied/Forbidden.

    A second PUT against a bucket that already has a replication configuration is
    an update, and real AWS rejects it with BadRequestException("A version token is
    not specified") unless the current versionToken from GetTableBucketReplication
    is echoed back — so fetch it first when a configuration already exists."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        kwargs: dict[str, Any] = {
            "tableBucketARN": src_arn,
            "configuration": {
                "role": role_arn,
                "rules": [{"destinations": [{"destinationTableBucketARN": dst_arn}]}],
            },
        }
        version_token = _current_replication_version_token(s3tables, src_arn)
        if version_token is not None:
            kwargs["versionToken"] = version_token
        try:
            s3tables.put_table_bucket_replication(**kwargs)
            return
        except Exception as exc:  # noqa: BLE001
            code = _error_code(exc)
            if code not in ("AccessDeniedException", "ForbiddenException"):
                raise
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"PutTableBucketReplication never succeeded: {last_exc}")


def _current_replication_version_token(s3tables: Any, bucket_arn: str) -> str | None:
    try:
        return s3tables.get_table_bucket_replication(tableBucketARN=bucket_arn)["versionToken"]
    except Exception as exc:  # noqa: BLE001
        if _error_code(exc) == "NotFoundException":
            return None
        raise


def _replicate_until_completed(
    s3tables: Any,
    src_arn: str,
    role_arn: str,
    dst_arn: str,
    table_arn: str,
    *,
    timeout_s: float,
) -> dict:
    """Configure bucket-level replication and poll to a terminal per-destination
    status. Real AWS observed here reports the freshly-created role's own policy as
    "insufficient permissions" for one or more attempts even after the accepted
    PutTableBucketReplication call — the replication attempt starts before the
    role's policy has fully propagated, distinct from the AccessDenied on the PUT
    call itself that `_put_bucket_replication_with_retry` already handles. Treat a
    permissions-flavored FAILED the same way: re-issue the configuration and poll
    again, bounded by one overall deadline."""
    deadline = time.monotonic() + timeout_s
    last_status: dict | None = None
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        _put_bucket_replication_with_retry(
            s3tables, src_arn, role_arn, dst_arn, timeout_s=min(60.0, max(5.0, remaining))
        )
        remaining = deadline - time.monotonic()
        status = _poll_until(
            lambda: s3tables.get_table_replication_status(tableArn=table_arn),
            lambda r: bool(r.get("destinations"))
            and str(r["destinations"][0].get("replicationStatus", "")).upper() != "PENDING",
            timeout_s=max(5.0, remaining),
            interval_s=10.0,
        )
        last_status = status
        dest = status["destinations"][0]
        state = str(dest.get("replicationStatus", "")).upper()
        if state == "COMPLETED":
            return status
        if state == "FAILED" and "permission" in str(dest.get("failureMessage", "")).lower():
            time.sleep(2)
            continue
        raise AssertionError(f"replication reached unexpected terminal state: {dest!r}")
    raise AssertionError(
        f"replication never reached COMPLETED within {timeout_s}s, last={last_status!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
