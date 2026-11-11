"""import-image-task-state-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "import-image-task-state-transitions"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportImage creates a task that starts in an active/pending state, and
    CancelImportTask moves it to a terminal deleting/deleted state."""
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-imgimport-")

    bucket = name.replace("_", "-")
    create_kwargs: dict[str, Any] = {"Bucket": bucket}
    # us-east-1 is a genuine S3 API quirk, not an account/region assumption: passing
    # CreateBucketConfiguration with LocationConstraint=us-east-1 there is itself rejected.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": name}]})

    def _empty_and_delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)

    key = "disk.raw"
    s3.put_object(Bucket=bucket, Key=key, Body=b"\x00" * (10 * 1024 * 1024))

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "vmie.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:Externalid": "vmimport"}},
            }
        ],
    }
    perms_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:ModifySnapshotAttribute",
                    "ec2:CopySnapshot",
                    "ec2:RegisterImage",
                    "ec2:Describe*",
                ],
                "Resource": "*",
            },
        ],
    }
    role_name = name + "-role"
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": name}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="vmimport-perms", PolicyDocument=json.dumps(perms_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="vmimport-perms"))

    import_task_id = _retry_until_success(
        lambda: ec2.import_image(
            DiskContainers=[{"Format": "RAW", "UserBucket": {"S3Bucket": bucket, "S3Key": key}}],
            RoleName=role_name,
            TagSpecifications=[
                {"ResourceType": "import-image-task", "Tags": [{"Key": "sim2real", "Value": name}]}
            ],
        )["ImportTaskId"],
        timeout_s=90,
        interval_s=5,
    )
    ctx.on_cleanup(
        lambda: _ignore_error(lambda: ec2.cancel_import_task(ImportTaskId=import_task_id))
    )

    def _task():
        tasks = ec2.describe_import_image_tasks(ImportTaskIds=[import_task_id])[
            "ImportImageTasks"
        ]
        return tasks[0] if tasks else None

    started = _poll_until(
        _task, lambda t: t is not None and t.get("Status") is not None, timeout_s=60, interval_s=3
    )
    assert started["Status"] not in ("deleted", "deleting"), (
        f"expected a freshly created import task to start in a non-terminal state, "
        f"got Status={started['Status']!r}"
    )

    cancel_resp = ec2.cancel_import_task(ImportTaskId=import_task_id)
    assert cancel_resp["ImportTaskId"] == import_task_id, (
        f"expected CancelImportTask to echo {import_task_id!r}, got {cancel_resp['ImportTaskId']!r}"
    )

    # CancelImportTask's own response carries no State/PreviousState on real AWS for a task
    # still in an early (e.g. "active") status -- only ImportTaskId comes back -- so the
    # transition is proven via an independent read instead of the mutating call's reply.
    moved = _poll_until(
        _task,
        lambda t: t is None or t.get("Status") != started["Status"],
        timeout_s=60,
        interval_s=3,
    )
    moved_status = moved["Status"] if moved else None
    assert moved is None or moved_status != started["Status"], (
        f"expected an independent DescribeImportImageTasks read to show the task move off its "
        f"pre-cancel status {started['Status']!r}, still {moved_status!r}"
    )

    final = _poll_until(
        _task,
        lambda t: t is None or t.get("Status") in ("deleted", "cancelled"),
        timeout_s=300,
        interval_s=10,
    )
    assert final is None or final["Status"] in ("deleted", "cancelled"), (
        f"expected the task to reach a terminal deleted/cancelled state via an independent "
        f"DescribeImportImageTasks read, got Status={final['Status']!r}"
    )


def _error_code(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _ignore_error(fn: Callable[[], Any]) -> None:
    _error_code(fn)


def _retry_until_success(fn: Callable[[], Any], *, timeout_s: float, interval_s: float) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation kept failing until timeout: {last_exc}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
