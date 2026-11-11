"""put-table-bucket-replication-malformed-config-rejected."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-replication-malformed-config-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableBucketReplication with a malformed destination table bucket ARN is rejected with
    ValidationException and persists nothing; a well-formed destination then succeeds."""
    s3t = ctx.client("s3tables")
    source_arn, dest_arn = _create_table_bucket_pair(ctx)
    role_arn = _create_replication_role(ctx, source_arn, dest_arn)

    malformed_config = {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": "not-an-arn"}]}]}
    code, message = _error(
        lambda: s3t.put_table_bucket_replication(tableBucketARN=source_arn, configuration=malformed_config)
    )
    assert code == "ValidationException", f"code={code}"
    expected = (
        "1 validation error detected: Value at "
        "'configuration.rules.1.member.destinations.1.member.destinationTableBucketARN' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "(arn:aws[-a-z0-9]*:[a-z0-9]+:[-a-z0-9]*:[0-9]{12}:bucket/[a-z0-9_-]{3,63})"
    )
    assert message == expected, f"message={message!r}"

    # Effect absent: no replication configuration was persisted by the rejected call.
    get_code, get_message = _error(lambda: s3t.get_table_bucket_replication(tableBucketARN=source_arn))
    assert get_code == "NotFoundException", f"get_code={get_code}"
    assert get_message == "The specified replication configuration does not exist.", (
        f"get_message={get_message!r}"
    )

    # Positive control: a well-formed destination ARN with a real, usable replication role
    # succeeds. Role trust/permission propagation is eventually consistent (undocumented
    # duration, commonly seconds to ~1 minute) -- poll rather than asserting immediately at the
    # propagation boundary.
    valid_config = {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}]}
    established = _retry_until_role_ready(
        lambda: s3t.put_table_bucket_replication(tableBucketARN=source_arn, configuration=valid_config)
    )
    _register_replication_cleanup(ctx, source_arn)
    assert "versionToken" in established, f"established={established}"

    current = s3t.get_table_bucket_replication(tableBucketARN=source_arn)
    got_dest = current["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
    assert got_dest == dest_arn, f"got_dest={got_dest} expected={dest_arn}"


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, because
    accepting input AWS refuses is a distinct failure from returning the wrong error code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _is_bucket_quota_error(exc: ClientError) -> bool:
    err = exc.response["Error"]
    return err["Code"] == "BadRequestException" and "more buckets than are allowed" in err.get(
        "Message", ""
    )


def _create_table_bucket_pair(ctx, timeout_s: float = 240.0, interval_s: float = 5.0):
    # The account-level table-bucket quota (default 10 per Region) is shared with every other
    # concurrently-running check. Acquire source+dest as a single atomic unit: if the dest can't
    # be obtained, roll back the source immediately rather than holding a scarce slot while
    # blocked, then retry the whole pair after a jittered backoff -- this avoids a multi-bucket
    # check permanently starving (or deadlocking against) single-bucket checks under contention.
    s3t = ctx.client("s3tables")
    deadline = time.monotonic() + timeout_s
    while True:
        source_arn = None
        try:
            source_arn = s3t.create_table_bucket(name=ctx.unique_name("sim2real-s3t-src-"))["arn"]
            dest_arn = s3t.create_table_bucket(name=ctx.unique_name("sim2real-s3t-dst-"))["arn"]
        except ClientError as exc:
            if source_arn is not None:
                _safe(lambda: s3t.delete_table_bucket(tableBucketARN=source_arn))
            if _is_bucket_quota_error(exc) and time.monotonic() < deadline:
                time.sleep(interval_s + random.uniform(0, interval_s))
                continue
            raise
        ctx.on_cleanup(lambda: _safe(lambda: s3t.delete_table_bucket(tableBucketARN=source_arn)))
        ctx.on_cleanup(lambda: _safe(lambda: s3t.delete_table_bucket(tableBucketARN=dest_arn)))
        return source_arn, dest_arn


def _create_replication_role(ctx, source_bucket_arn: str, dest_bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3tbrepl-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "replication.s3tables.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real s3tables replication behavioral-check role",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    perms = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3tables:GetTable",
                    "s3tables:GetTableMetadataLocation",
                    "s3tables:GetTableMaintenanceConfiguration",
                    "s3tables:GetTableData",
                ],
                "Resource": f"{source_bucket_arn}/table/*",
            },
            {"Effect": "Allow", "Action": ["s3tables:ListTables"], "Resource": source_bucket_arn},
            {
                "Effect": "Allow",
                "Action": ["s3tables:CreateTable", "s3tables:CreateNamespace"],
                "Resource": dest_bucket_arn,
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3tables:PutTableData",
                    "s3tables:GetTableData",
                    "s3tables:UpdateTableMetadataLocation",
                    "s3tables:PutTableMaintenanceConfiguration",
                ],
                "Resource": f"{dest_bucket_arn}/table/*",
            },
        ],
    }
    policy_name = "sim2real-s3tbrepl-perms"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(perms))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))
    return role_arn


def _retry_until_role_ready(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code not in ("AccessDeniedException", "ForbiddenException"):
                raise
            time.sleep(interval_s)
    raise AssertionError(f"replication role never became usable within {timeout_s}s, last error={last_code}")


def _register_replication_cleanup(ctx, bucket_arn: str) -> None:
    s3t = ctx.client("s3tables")

    def _cleanup():
        try:
            token = s3t.get_table_bucket_replication(tableBucketARN=bucket_arn)["versionToken"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _GONE:
                raise
            return
        _safe(lambda: s3t.delete_table_bucket_replication(tableBucketARN=bucket_arn, versionToken=token))

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
