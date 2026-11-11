"""update-stream-record-distribution-strategy-nonexistent-stream-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stream-record-distribution-strategy-nonexistent-stream-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStreamRecordDistributionStrategy on a never-created stream ARN fails with
    ResourceNotFoundException naming stream and account, while the identical call on a real
    on-demand stream succeeds."""
    kinesis = ctx.client("kinesis")

    missing_name = ctx.unique_name("sim2real-kinrds-missing-")
    missing_arn = f"arn:aws:kinesis:{ctx.region}:{ctx.account}:stream/{missing_name}"

    code, message = _error_code_and_message(
        lambda: kinesis.update_stream_record_distribution_strategy(
            StreamARN=missing_arn, RecordDistributionStrategy="AUTO"
        )
    )
    assert code == "ResourceNotFoundException", (
        f"UpdateStreamRecordDistributionStrategy on a never-created stream gave code "
        f"{code!r}, expected ResourceNotFoundException"
    )
    expected_message = f"Stream {missing_name} under account {ctx.account} not found."
    assert message == expected_message, (
        f"UpdateStreamRecordDistributionStrategy on a never-created stream gave message "
        f"{message!r}, expected {expected_message!r}"
    )

    real_name = ctx.unique_name("sim2real-kinrds-real-")
    kinesis.create_stream(
        StreamName=real_name, StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "kinrds-real"},
    )
    ctx.on_cleanup(lambda: _delete_stream_ignore_missing(ctx, real_name))
    real_summary = _wait_stream_status(ctx, real_name, {"ACTIVE"}, timeout_s=180)
    real_arn = real_summary["StreamARN"]

    resp = kinesis.update_stream_record_distribution_strategy(
        StreamARN=real_arn, RecordDistributionStrategy="AUTO"
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        "the identical call against a stream that DOES exist (the positive control) must "
        f"succeed; got HTTP {resp['ResponseMetadata']['HTTPStatusCode']}"
    )


def _delete_stream_ignore_missing(ctx, name: str) -> None:
    try:
        ctx.client("kinesis").delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_stream_status(ctx, name: str, target_statuses, timeout_s: float = 180.0) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] in target_statuses:
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {name} did not reach {target_statuses} in {timeout_s}s (last={summary})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
