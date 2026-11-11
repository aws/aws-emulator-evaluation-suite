"""concurrent-synchronization-config-updates-optimistic-lock."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-synchronization-config-updates-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["s3files"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N racers updating a synchronization configuration with the same base version: exactly one wins."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    s3files = ctx.client("s3files")
    bucket = _create_versioned_bucket(ctx, teardown_deadline)
    role_arn = _create_s3files_role(ctx, bucket["name"])
    fs_id = _create_and_wait_available(ctx, bucket["arn"], role_arn, teardown_deadline)

    baseline_put = s3files.put_synchronization_configuration(
        fileSystemId=fs_id,
        importDataRules=[{"prefix": "", "trigger": "ON_FILE_ACCESS", "sizeLessThan": 1048576}],
        expirationDataRules=[{"daysAfterLastAccess": 30}],
    )
    assert not baseline_put or "latestVersionNumber" not in baseline_put, "PutSynchronizationConfiguration returns an empty body"
    base_version = s3files.get_synchronization_configuration(fileSystemId=fs_id)["latestVersionNumber"]

    n_racers = 6

    def _racer(idx):
        try:
            # importDataRules must always include a rule with prefix "" (real AWS rejects a put
            # without one, independent of latestVersionNumber); the expiration rule carries the
            # per-racer identity instead so the winner is unambiguous from a single field.
            s3files.put_synchronization_configuration(
                fileSystemId=fs_id,
                latestVersionNumber=base_version,
                importDataRules=[{"prefix": "", "trigger": "ON_FILE_ACCESS", "sizeLessThan": 1048576}],
                expirationDataRules=[{"daysAfterLastAccess": 30 + idx}],
            )
            return {"idx": idx, "ok": True, "code": None, "Message": None}
        except ClientError as err:
            return {"idx": idx, "ok": False, "code": err.response["Error"]["Code"],
                    "Message": err.response["Error"].get("Message")}

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(_racer, range(n_racers)))

    winners = [r for r in results if r["ok"]]
    losers = [r for r in results if not r["ok"]]

    assert len(winners) == 1, f"expected exactly 1 racer to win the optimistic-lock race, got {len(winners)}: {results}"
    assert len(losers) == n_racers - 1, f"expected {n_racers - 1} losers, got {len(losers)}: {results}"
    assert all(loser["code"] == "ConflictException" for loser in losers), f"expected every loser to get ConflictException, got {losers}"
    stale = "Invalid latestVersionNumber. Retrieve the most recent latestVersionNumber and retry."
    assert all(loser["Message"] == stale for loser in losers), f"expected every loser to say {stale!r}, got {losers}"

    winner_idx = winners[0]["idx"]
    final = s3files.get_synchronization_configuration(fileSystemId=fs_id)
    assert final["expirationDataRules"] == [{"daysAfterLastAccess": 30 + winner_idx}], (
        f"expected the persisted configuration to reflect the single winner (racer-{winner_idx}), got {final['expirationDataRules']}"
    )
    assert final["latestVersionNumber"] != base_version, (
        f"expected the version to advance past the base {base_version} after the winning update, got {final['latestVersionNumber']}"
    )


_CLEANUP_S = 900.0


def _cleanup_deadline(teardown_deadline) -> float:
    """The monotonic instant all of this run's teardowns stop retrying at."""
    return teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_S)


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_versioned_bucket(ctx, teardown_deadline):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-s3files-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        # The file system's asynchronous detach keeps the bucket refused until it completes.
        while True:
            try:
                s3.delete_bucket(Bucket=name)
                return
            except ClientError as err:
                if (err.response["Error"]["Code"] != "BucketHasS3FileSystemAttached"
                        or time.monotonic() >= _cleanup_deadline(teardown_deadline)):
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _create_s3files_role(ctx, bucket_name):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-s3files-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowS3FilesAssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "elasticfilesystem.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
        }],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetObject*", "s3:PutObject*",
                       "s3:DeleteObject*", "s3:AbortMultipartUpload"],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3files-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3files-access"))
    return role_arn


def _create_and_wait_available(ctx, bucket_arn, role_arn, teardown_deadline, **kwargs):
    s3files = ctx.client("s3files")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = s3files.create_file_system(bucket=bucket_arn, roleArn=role_arn, **kwargs)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException"):
                last_err = err
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    fs_id = resp["fileSystemId"]
    ctx.on_cleanup(lambda: _delete_file_system_and_wait(ctx, s3files, fs_id, teardown_deadline))
    _poll_until(
        lambda: s3files.get_file_system(fileSystemId=fs_id)["status"],
        lambda s: s == "available",
        timeout_s=300.0,
        interval_s=5.0,
    )
    return fs_id


def _delete_file_system_and_wait(ctx, s3files, fs_id, teardown_deadline):
    """Delete the file system and wait until GetFileSystem answers ResourceNotFoundException."""
    try:
        s3files.delete_file_system(fileSystemId=fs_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    while True:
        try:
            s3files.get_file_system(fileSystemId=fs_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= _cleanup_deadline(teardown_deadline):
            raise AssertionError(f"file system {fs_id} still exists at the cleanup deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
