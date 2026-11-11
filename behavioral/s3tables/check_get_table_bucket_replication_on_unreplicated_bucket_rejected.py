"""get-table-bucket-replication-on-unreplicated-bucket-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-table-bucket-replication-on-unreplicated-bucket-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableBucketReplication on a bucket without replication returns NotFoundException, not an empty
    success; the same call succeeds once a replication configuration is put (positive control)."""
    s3t = ctx.client("s3tables")
    source_arn = _create_bucket(ctx, "replsrc")

    code, message = _error(lambda: s3t.get_table_bucket_replication(tableBucketARN=source_arn))
    assert code == "NotFoundException", f"expected NotFoundException on unreplicated bucket, got {code!r}"
    assert message == "The specified replication configuration does not exist.", (
        f"expected the exact not-found message on the unreplicated bucket, got {message!r}"
    )

    # Positive control: put a real replication configuration, then Get succeeds.
    dest_arn = _create_bucket(ctx, "repldst")
    role_arn = _create_replication_role(ctx)
    config = {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}]}
    _call_with_retry(
        lambda: s3t.put_table_bucket_replication(tableBucketARN=source_arn, configuration=config),
        retryable_codes={"AccessDeniedException", "ForbiddenException"},
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: s3t.delete_table_bucket_replication(
                tableBucketARN=source_arn,
                versionToken=s3t.get_table_bucket_replication(tableBucketARN=source_arn)["versionToken"],
            )
        )
    )

    got = s3t.get_table_bucket_replication(tableBucketARN=source_arn)
    got_dest = got["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
    assert got_dest == dest_arn, f"expected destination {dest_arn!r}, got {got_dest!r}"
    assert got["versionToken"], "expected a non-empty versionToken once replication is configured"

    # The delete is already registered for cleanup; assert it too, so the delete is proven to
    # remove the configuration rather than merely being trusted to run at teardown. Real AWS
    # rejects DeleteTableBucketReplication with BadRequestException unless versionToken is
    # supplied, even though the model does not mark it required.
    s3t.delete_table_bucket_replication(tableBucketARN=source_arn, versionToken=got["versionToken"])
    code_after_delete, message_after_delete = _error(
        lambda: s3t.get_table_bucket_replication(tableBucketARN=source_arn)
    )
    assert code_after_delete == "NotFoundException", (
        f"expected NotFoundException after deleting replication, got {code_after_delete!r}"
    )
    assert message_after_delete == "The specified replication configuration does not exist.", (
        f"expected the exact not-found message after deleting replication, got {message_after_delete!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _create_bucket(ctx, suffix: str) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_replication_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3trep-")[:64]
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3tables:*", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3tables-replication-access", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3tables-replication-access")
        )
    )
    return role_arn


def _call_with_retry(fn, retryable_codes, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in retryable_codes:
                raise
            last_err = err
            time.sleep(interval_s)
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
