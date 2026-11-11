"""op-contract-create-restore-image-task-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-restore-image-task-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRestoreImageTask: DryRun proves the request shape is accepted (surrogate for the
    success path, since a real restore requires a previously completed CreateStoreImageTask that
    can take many minutes to hours); a nonexistent S3 source is rejected with a real error."""
    ec2 = ctx.client("ec2")
    bucket = ctx.unique_name("sim2real-restore-bucket-")
    key = "amis/does-not-exist.bin"

    # Success-path surrogate: DryRun short-circuits before touching S3, proving the request is
    # well-formed and would be authorized to proceed.
    dry_run_code, dry_run_message = _client_error(
        lambda: ec2.create_restore_image_task(Bucket=bucket, ObjectKey=key, DryRun=True)
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    expected_dry_run = "Request would have succeeded, but DryRun flag is set."
    assert dry_run_message == expected_dry_run, (
        f"expected message {expected_dry_run!r}, got {dry_run_message!r}"
    )

    # Error boundary: a bucket/object that does not exist must be rejected with a real error.
    # message varies: it embeds the per-request S3 Request ID and Extended Request ID.
    code, _message = _client_error(lambda: ec2.create_restore_image_task(Bucket=bucket, ObjectKey=key))
    assert code == "InvalidRequest", f"expected InvalidRequest, got {code!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
