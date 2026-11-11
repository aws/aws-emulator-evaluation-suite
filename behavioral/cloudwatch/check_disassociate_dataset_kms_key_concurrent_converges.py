"""disassociate-dataset-kms-key-concurrent-converges."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "disassociate-dataset-kms-key-concurrent-converges"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DisassociateDatasetKmsKey racing against a concurrent AssociateDatasetKmsKey on the
    same dataset resolves atomically: the loser (if any) is rejected with ConflictException and
    the final GetDataset state matches exactly the winning operation, never a corrupted mix."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "disassociate_dataset_kms_key"):
        raise AssertionError("cloudwatch client does not support DisassociateDatasetKmsKey")

    key_a = _create_kms_key_for_dataset(ctx)
    key_b = _create_kms_key_for_dataset(ctx)

    _safe_disassociate(cw)
    cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_a["arn"])
    ctx.on_cleanup(lambda: _safe_disassociate(cw))

    outcomes: dict[str, str] = {}
    messages: dict[str, str] = {}

    def do_associate() -> None:
        try:
            cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_b["arn"])
            outcomes["associate"] = "ok"
        except ClientError as e:
            outcomes["associate"] = e.response.get("Error", {}).get("Code", "Unknown")
            messages["associate"] = e.response.get("Error", {}).get("Message", "")

    def do_disassociate() -> None:
        try:
            cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
            outcomes["disassociate"] = "ok"
        except ClientError as e:
            outcomes["disassociate"] = e.response.get("Error", {}).get("Code", "Unknown")

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(do_associate), ex.submit(do_disassociate)]
        for f in futures:
            f.result()

    for tag, outcome in outcomes.items():
        if outcome != "ok":
            assert outcome == "ConflictException", f"{tag}: unexpected outcome {outcome!r}"
            if tag == "associate":
                # The message ends with a per-request id; the text before it is stable.
                assert messages[tag].partition(", Request ID: ")[0] == (
                    "The conditional request failed (Service: DynamoDb, Status Code: 400"
                ), f"{tag}: unexpected message {messages[tag]!r}"

    final_arn = cw.get_dataset(DatasetIdentifier="default").get("KmsKeyArn")
    if outcomes["disassociate"] == "ok" and outcomes["associate"] != "ok":
        assert final_arn is None, f"disassociate won the race but KmsKeyArn is still {final_arn!r}"
    elif outcomes["associate"] == "ok" and outcomes["disassociate"] != "ok":
        assert final_arn == key_b["arn"], f"associate won the race but final key is {final_arn!r}"
    elif outcomes["associate"] == "ok" and outcomes["disassociate"] == "ok":
        # Both succeeded: no conflict was detected between the racers, so they applied
        # serially in some order. Either final value is legitimate, but key_a's original
        # association cannot survive -- one of the two mutations necessarily overwrote or
        # removed it.
        assert final_arn in (None, key_b["arn"]), (
            f"both racers reported success but the prior association survived unchanged: {final_arn!r}"
        )
    else:
        # Both hit ConflictException: neither mutation took effect, so the original
        # association must be untouched.
        assert final_arn == key_a["arn"], (
            f"both racers were rejected with ConflictException but final key is {final_arn!r}"
        )


from botocore.exceptions import ClientError  # noqa: E402


def _safe_disassociate(cw: Any) -> None:
    try:
        cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _iam_principal_arn(ctx: Any) -> str:
    sts = ctx.client("sts")
    arn = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        parts = arn.split(":")
        account = parts[4]
        role_name = parts[5].split("/")[1]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _wait_key_state(kms: Any, key_id: str, expected_state: str, timeout_s: float = 30.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
        if last == expected_state:
            return last
        time.sleep(1.0)
    raise AssertionError(f"KMS key {key_id} never reached state {expected_state}, last={last}")


def _create_kms_key_for_dataset(ctx: Any, deny_caller_decrypt: bool = False) -> dict[str, str]:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-cw-dataset-"),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
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
    if deny_caller_decrypt:
        policy["Statement"].append(
            {
                "Sid": "DenyCallerDecrypt",
                "Effect": "Deny",
                "Principal": {"AWS": _iam_principal_arn(ctx)},
                "Action": "kms:Decrypt",
                "Resource": "*",
            }
        )
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(policy))
    _wait_key_state(kms, key_id, "Enabled")
    return {"id": key_id, "arn": key_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
