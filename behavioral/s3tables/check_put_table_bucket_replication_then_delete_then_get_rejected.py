"""put-table-bucket-replication-then-delete-then-get-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-replication-then-delete-then-get-rejected"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteTableBucketReplication, GetTableBucketReplication fails rather than returning the removed
    config; a fresh Put/Get on the same bucket still succeeds, so the failure is the absent state."""
    s3tables = ctx.client("s3tables")
    source_arn = _create_table_bucket(ctx, "brepl-src")
    dest_arn = _create_table_bucket(ctx, "brepl-dst")
    role_arn = _create_replication_role(ctx)

    configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}],
    }
    put_resp = _retry_on_access_denied(
        lambda: s3tables.put_table_bucket_replication(
            tableBucketARN=source_arn, configuration=configuration
        )
    )
    version_token = put_resp["versionToken"]

    # Positive control: configuration we just wrote round-trips.
    got = s3tables.get_table_bucket_replication(tableBucketARN=source_arn)
    assert got["configuration"]["role"] == role_arn, (
        f"expected role {role_arn!r}, got {got['configuration'].get('role')!r}"
    )
    assert (
        got["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
        == dest_arn
    ), (
        f"expected destination {dest_arn!r}, got "
        f"{got['configuration']['rules'][0]['destinations'][0].get('destinationTableBucketARN')!r}"
    )

    s3tables.delete_table_bucket_replication(tableBucketARN=source_arn, versionToken=version_token)

    code, message = _error(lambda: s3tables.get_table_bucket_replication(tableBucketARN=source_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "The specified replication configuration does not exist.", (
        f"message={message!r}"
    )

    # Restore: re-establishing replication on the same bucket still works. This is
    # the beat that separates "the config was removed" from "the bucket/role/API is
    # now broken" -- without it, a target that permanently wedges replication after
    # any delete would still pass.
    restore_resp = _retry_on_access_denied(
        lambda: s3tables.put_table_bucket_replication(
            tableBucketARN=source_arn, configuration=configuration
        )
    )
    ctx.on_cleanup(
        lambda: _delete_bucket_replication(s3tables, source_arn)
    )
    assert restore_resp["versionToken"], "expected a versionToken on the restored replication"

    revived = s3tables.get_table_bucket_replication(tableBucketARN=source_arn)
    assert revived["configuration"]["role"] == role_arn, (
        f"expected revived role {role_arn!r}, got {revived['configuration'].get('role')!r}"
    )
    assert (
        revived["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
        == dest_arn
    ), (
        f"expected revived destination {dest_arn!r}, got "
        f"{revived['configuration']['rules'][0]['destinations'][0].get('destinationTableBucketARN')!r}"
    )


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _delete_bucket_replication(s3t, bucket_arn: str) -> None:
    """DeleteTableBucketReplication requires the current versionToken; no config left is gone."""
    try:
        token = s3t.get_table_bucket_replication(tableBucketARN=bucket_arn)["versionToken"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise
        return
    _safe(lambda: s3t.delete_table_bucket_replication(tableBucketARN=bucket_arn, versionToken=token))


def _create_table_bucket(ctx, suffix: str) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: s3tables.delete_table_bucket(tableBucketARN=arn)))
    return arn


def _create_replication_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3t-repl-role-")[:64]
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
        Description="sim2real s3tables replication test role",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_name = "sim2real-s3t-repl-permissions"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3tables:*"], "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    return role_arn


def _retry_on_access_denied(fn, timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
    # Freshly created IAM roles can take a few seconds to become assumable
    # (IAM eventual consistency); retry past that window rather than failing on it.
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ForbiddenException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
