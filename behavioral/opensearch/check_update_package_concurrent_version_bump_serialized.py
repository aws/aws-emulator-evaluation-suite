"""update-package-concurrent-version-bump-serialized."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-package-concurrent-version-bump-serialized"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Back-to-back UpdatePackage calls on one package: exactly one wins, the rest fail
    BaseException "not in desired state"; each rejected call's retry after settling lands in
    the version history, and the package ends AVAILABLE."""
    opensearch = ctx.client("opensearch")
    package_id, bucket = _create_txt_package(ctx)
    _wait_package_available(ctx, package_id)

    commit_messages = [f"sim2real-bump-{i}" for i in range(3)]
    # The winner moves the package to COPYING; the others follow sequentially inside that busy
    # window (a true race has no documented outcome). Sources are uploaded first.
    keys = [f"sim2real-dict-v{i + 2}.txt" for i in range(len(commit_messages))]
    for i, key in enumerate(keys):
        ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=f"sim2real, test, bump{i}\n".encode())

    def _bump(i: int, commit_message: str):
        return opensearch.update_package(
            PackageID=package_id,
            PackageSource={"S3BucketName": bucket, "S3Key": keys[i]},
            CommitMessage=commit_message,
        )

    results: list[tuple[str, object]] = []
    for i, msg in enumerate(commit_messages):
        try:
            results.append((msg, ("ok", _bump(i, msg))))
        except Exception as exc:  # noqa: BLE001 - captured for the assertion below
            results.append((msg, ("error", exc)))

    successes = [msg for msg, (kind, _) in results if kind == "ok"]
    rejected = [(msg, exc) for msg, (kind, exc) in results if kind == "error"]
    assert len(successes) == 1, (
        f"expected exactly one of {len(commit_messages)} concurrent UpdatePackage calls to win "
        f"(the package can only be in desired state for one writer at a time), "
        f"got {len(successes)} successes: {results!r}"
    )
    assert len(successes) + len(rejected) == len(commit_messages), (
        f"expected every one of {len(commit_messages)} concurrent calls to resolve to either a "
        f"success or an error, got {results!r}"
    )

    from botocore.exceptions import ClientError

    for msg, exc in rejected:
        assert isinstance(exc, ClientError), f"{msg}: unexpected non-ClientError rejection {exc!r}"
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "BaseException", (
            f"{msg}: expected the busy-package rejection BaseException, got {code!r}: {exc!r}"
        )
        assert message == "Operation not allowed. The package is not in desired state.", (
            f"{msg}: unexpected busy-package rejection message {message!r}"
        )

    _wait_package_available(ctx, package_id, timeout_s=180.0)

    history = opensearch.get_package_version_history(PackageID=package_id)["PackageVersionHistoryList"]
    seen_commits = {entry.get("CommitMessage") for entry in history}
    missing_winners = [msg for msg in successes if msg not in seen_commits]
    assert not missing_winners, (
        f"winning update(s) not reflected in version history: {missing_winners} not in {history!r}"
    )

    for msg, _exc in rejected:
        idx = commit_messages.index(msg)
        key = f"sim2real-dict-retry-v{idx}.txt"
        ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=f"sim2real, retry, {msg}\n".encode())
        retry_msg = f"{msg}-retry"
        opensearch.update_package(
            PackageID=package_id,
            PackageSource={"S3BucketName": bucket, "S3Key": key},
            CommitMessage=retry_msg,
        )
        _wait_package_available(ctx, package_id, timeout_s=180.0)
        history = opensearch.get_package_version_history(PackageID=package_id)["PackageVersionHistoryList"]
        seen_commits = {entry.get("CommitMessage") for entry in history}
        assert retry_msg in seen_commits, f"retried update {retry_msg!r} lost, not in {history!r}"

    final = opensearch.describe_packages(Filters=[{"Name": "PackageID", "Value": [package_id]}])[
        "PackageDetailsList"
    ][0]
    assert final["PackageStatus"] == "AVAILABLE", f"package settled in unexpected status {final!r}"


def _create_txt_package(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    opensearch = ctx.client("opensearch")
    bucket = ctx.unique_name("sim2real-ospkg-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    key = "sim2real-dict-v1.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real, test\n")
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "es.amazonaws.com"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    }
                ],
            }
        ),
    )

    name = ctx.unique_name("sim2real-pkg-").replace("_", "-").lower()[:40]
    resp = opensearch.create_package(
        PackageName=name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
        PackageDescription="sim2real test dictionary",
    )
    package_id = resp["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: opensearch.delete_package(PackageID=package_id))
    return package_id, bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    finally:
        s3.delete_bucket(Bucket=bucket)


def _wait_package_available(ctx, package_id: str, timeout_s: float = 180.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"][0]
        status = details["PackageStatus"]
        if status == "AVAILABLE":
            return
        if status in ("COPY_FAILED", "VALIDATION_FAILED"):
            raise AssertionError(f"package {package_id} entered {status}")
        time.sleep(5)
    raise AssertionError(f"package {package_id} did not settle to AVAILABLE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
