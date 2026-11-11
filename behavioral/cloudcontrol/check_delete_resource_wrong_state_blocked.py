"""delete-resource-wrong-state-blocked."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-resource-wrong-state-blocked"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResource of a non-empty S3 bucket resolves FAILED with ErrorCode
    GeneralServiceException and leaves the bucket in place; once emptied, the delete
    succeeds and GetResource answers ResourceNotFoundException."""
    cc = ctx.client("cloudcontrol")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-behav-ccbucket-").lower()
    create_progress = cc.create_resource(
        TypeName="AWS::S3::Bucket",
        DesiredState=json.dumps(
            {
                "BucketName": bucket_name,
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ),
    )["ProgressEvent"]
    ctx.on_cleanup(lambda: _force_delete_bucket(s3, bucket_name))
    create_final = _poll_request_status(ctx, create_progress["RequestToken"])
    assert create_final["OperationStatus"] == "SUCCESS", (
        f"bucket create did not reach SUCCESS: {create_final}"
    )

    # Blocking dependency: an object inside the bucket.
    s3.put_object(Bucket=bucket_name, Key="blocker.txt", Body=b"blocking-content")

    delete_progress = cc.delete_resource(TypeName="AWS::S3::Bucket", Identifier=bucket_name)[
        "ProgressEvent"
    ]
    delete_final = _poll_request_status(ctx, delete_progress["RequestToken"])
    assert delete_final["OperationStatus"] == "FAILED", f"unexpected final status: {delete_final}"
    # S3's "bucket not empty" 409 doesn't map to CC's dedicated ResourceConflict
    # code; it surfaces as the generic downstream-service-error bucket instead.
    assert delete_final.get("ErrorCode") == "GeneralServiceException", (
        f"unexpected ErrorCode: {delete_final}"
    )
    # message varies: StatusMessage embeds the downstream S3 Request ID and Extended Request ID

    # Effect absent: the bucket (and its object) are still there.
    s3.head_bucket(Bucket=bucket_name)

    # Positive control: clear the dependency, then the delete succeeds.
    s3.delete_object(Bucket=bucket_name, Key="blocker.txt")
    retry_progress = cc.delete_resource(TypeName="AWS::S3::Bucket", Identifier=bucket_name)[
        "ProgressEvent"
    ]
    retry_final = _poll_request_status(ctx, retry_progress["RequestToken"])
    assert retry_final["OperationStatus"] == "SUCCESS", f"unexpected retry status: {retry_final}"

    # Effect: Cloud Control's own view confirms the bucket is gone.
    cc_code, cc_message = _error(
        lambda: cc.get_resource(TypeName="AWS::S3::Bucket", Identifier=bucket_name)
    )
    assert cc_code == "ResourceNotFoundException", f"unexpected GetResource code: {cc_code}"
    expected = _handler_not_found(
        cc_message, "AWS::S3::Bucket Handler returned status FAILED: Bucket not found"
    )
    assert cc_message == expected, f"expected message {expected!r}, got {cc_message!r}"


def _error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _force_delete_bucket(s3, bucket_name: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _wait_for_bucket_gone(s3, bucket_name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_seen = "never raised"
    while time.monotonic() < deadline:
        try:
            s3.head_bucket(Bucket=bucket_name)
            last_seen = "still present"
        except botocore.exceptions.ClientError as err:
            status = err.response["ResponseMetadata"]["HTTPStatusCode"]
            if status == 404:
                return
            last_seen = f"status={status}"
        time.sleep(interval_s)
    raise AssertionError(f"bucket {bucket_name} never disappeared after delete; last={last_seen}")


def _poll_request_status(ctx, token, timeout_s=120.0, interval_s=3.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached a terminal status; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
