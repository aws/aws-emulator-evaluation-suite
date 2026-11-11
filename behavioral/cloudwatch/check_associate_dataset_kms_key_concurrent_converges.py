"""associate-dataset-kms-key-concurrent-converges."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "associate-dataset-kms-key-concurrent-converges"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two racing AssociateDatasetKmsKey calls on an associated dataset converge on a winner's key.

    At least one racer succeeds, any loser is rejected with ConflictException, and GetDataset
    then reports the key of a racer that succeeded.
    """
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "associate_dataset_kms_key"):
        raise AssertionError("cloudwatch client does not support AssociateDatasetKmsKey")

    key_a = _create_kms_key_for_dataset(ctx)
    key_b = _create_kms_key_for_dataset(ctx)
    key_c = _create_kms_key_for_dataset(ctx)

    _safe_disassociate(cw)
    cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_a["arn"])
    ctx.on_cleanup(lambda: _safe_disassociate(cw))

    outcomes: dict[str, str] = {}
    messages: dict[str, str] = {}

    def attempt(tag: str, arn: str) -> None:
        try:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=arn)
            outcomes[tag] = "ok"
        except ClientError as e:
            outcomes[tag] = e.response.get("Error", {}).get("Code", "Unknown")
            messages[tag] = e.response.get("Error", {}).get("Message", "")

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(attempt, "toB", key_b["arn"]), ex.submit(attempt, "toC", key_c["arn"])]
        for f in futures:
            f.result()

    for tag, outcome in outcomes.items():
        if outcome != "ok":
            assert outcome == "ConflictException", f"{tag}: unexpected outcome {outcome!r}"
            # The message ends with a per-request id; the text before it is stable.
            assert messages[tag].partition(", Request ID: ")[0] == (
                "The conditional request failed (Service: DynamoDb, Status Code: 400"
            ), f"{tag}: unexpected message {messages[tag]!r}"
    assert "ok" in outcomes.values(), f"expected at least one racer to succeed, got {outcomes}"

    winners = [arn for tag, arn in (("toB", key_b["arn"]), ("toC", key_c["arn"])) if outcomes[tag] == "ok"]
    final_arn = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")
    assert final_arn in winners, f"final KmsKeyArn {final_arn!r} is not among winning racers {winners}"


from botocore.exceptions import ClientError  # noqa: E402


def _safe_disassociate(cw: Any) -> None:
    try:
        cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_key_state(kms: Any, key_id: str, expected_state: str, timeout_s: float = 30.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if last == expected_state:
            return last
        time.sleep(1.0)
    raise AssertionError(f"KMS key {key_id} never reached state {expected_state}, last={last}")


def _create_kms_key_for_dataset(ctx: Any) -> dict[str, str]:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-"),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    policy["Statement"].append(
        {
            "Sid": "AllowCloudWatchDatasetUse",
            "Effect": "Allow",
            "Principal": {"Service": "cloudwatch.amazonaws.com"},
            "Action": [
                "kms:DescribeKey",
                "kms:GenerateDataKey",
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
            ],
            "Resource": "*",
        }
    )
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))
    _wait_key_state(kms, key_id, "Enabled")
    return {"id": key_id, "arn": key_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
