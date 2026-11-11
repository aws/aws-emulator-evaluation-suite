"""put-table-bucket-replication-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-table-bucket-replication-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3tables"]

MSG_NO_REPLICATION = "The specified replication configuration does not exist."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Configuring bucket-level replication transitions the bucket into a replicating
    state (GetTableBucketReplication returns the persisted role/destination); deleting
    the config returns it to non-replicating on the next get (NotFoundException)."""
    s3t = ctx.client("s3tables")
    source_arn = _create_table_bucket(ctx)
    dest_arn = _create_table_bucket(ctx)
    role_arn = _create_replication_role(ctx)

    configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}],
    }
    _retry_role_propagation(
        lambda: s3t.put_table_bucket_replication(
            tableBucketARN=source_arn, configuration=configuration
        )
    )

    got = s3t.get_table_bucket_replication(tableBucketARN=source_arn)
    assert got["configuration"]["role"] == role_arn, (
        f"expected persisted role {role_arn!r}, got {got['configuration'].get('role')!r}"
    )
    assert (
        got["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
        == dest_arn
    ), (
        f"expected persisted destination {dest_arn!r}, got "
        f"{got['configuration']['rules'][0]['destinations'][0].get('destinationTableBucketARN')!r}"
    )
    version_token = got["versionToken"]

    s3t.delete_table_bucket_replication(tableBucketARN=source_arn, versionToken=version_token)

    code, message = _error(lambda: s3t.get_table_bucket_replication(tableBucketARN=source_arn))
    assert code == "NotFoundException", (
        f"expected NotFoundException reading a deleted replication config, got {code!r}"
    )
    assert message == MSG_NO_REPLICATION, f"message={message!r}"

    # A mutation on the now-deleted config (not just a read) must also fail.
    code, message = _error(
        lambda: s3t.delete_table_bucket_replication(
            tableBucketARN=source_arn, versionToken=version_token
        )
    )
    assert code == "NotFoundException", (
        f"expected re-deleting an already-absent replication config to fail with "
        f"NotFoundException, got {code!r}"
    )
    assert message == MSG_NO_REPLICATION, f"message={message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(name=name, tags={"sim2real:managed": "true"})["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_replication_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3t-repl-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3tables:*", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3tables-replication",
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3tables-replication")
    )
    return role_arn


def _retry_role_propagation(
    fn: Callable[[], Any], *, timeout_s: float = 90.0, interval_s: float = 5.0
) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ForbiddenException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
