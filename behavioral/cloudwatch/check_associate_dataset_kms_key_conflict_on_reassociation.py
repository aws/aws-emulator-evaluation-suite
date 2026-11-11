"""associate-dataset-kms-key-conflict-on-reassociation."""
from __future__ import annotations

import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-dataset-kms-key-conflict-on-reassociation"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]
# The text before the per-request id, and the whole shape around it.
_CONFLICT_MESSAGE_HEAD = "The conditional request failed (Service: DynamoDb, Status Code: 400"
_CONFLICT_MESSAGE_RE = re.compile(
    r"The conditional request failed \(Service: DynamoDb, Status Code: 400, Request ID: [A-Z0-9]+\) "
    r"\(SDK Attempt Count: 1\)"
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Many concurrent AssociateDatasetKmsKey calls on the default dataset, each with its own key:
    at least one is applied, any refused one gets ConflictException, and GetDataset then reports
    the key of an applied call, never a refused call's key."""
    cw = ctx.client("cloudwatch")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    _safe_disassociate(cw)

    n_racers = 6
    key_arns = [_create_cw_ready_kms_key(ctx, kms, account_id) for _ in range(n_racers)]
    ctx.on_cleanup(lambda: _safe_disassociate(cw))

    barrier = threading.Barrier(n_racers)

    def _race(key_arn: str):
        barrier.wait()
        return _error(lambda: cw.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key_arn))

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(_race, key_arns))

    accepted = [arn for arn, r in zip(key_arns, results) if r is None]
    for r in results:
        if r is not None:
            code, message = r
            assert code == "ConflictException", f"undocumented AssociateDatasetKmsKey refusal: {code!r} ({message!r})"
            assert _CONFLICT_MESSAGE_RE.fullmatch(message or ""), (
                f"ConflictException message {message!r} does not match {_CONFLICT_MESSAGE_RE.pattern!r}"
            )
            assert message.partition(", Request ID: ")[0] == _CONFLICT_MESSAGE_HEAD, message
    assert accepted, f"every concurrent AssociateDatasetKmsKey call was refused: {results}"

    final = cw.get_dataset(DatasetIdentifier="default")
    assert final.get("KmsKeyArn") in accepted, (
        f"final KmsKeyArn {final.get('KmsKeyArn')!r} is not the key of an applied call"
    )


def _error(fn):
    """None if fn() succeeds, else the botocore (Error.Code, Error.Message) it raised."""
    try:
        fn()
        return None
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")


def _safe_disassociate(cw) -> None:
    try:
        cw.disassociate_dataset_kms_key(DatasetIdentifier="default")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _cw_ready_key_policy(account_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudWatchService",
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
            },
        ],
    }


def _create_cw_ready_kms_key(ctx, kms, account_id: str) -> str:
    policy = _cw_ready_key_policy(account_id)
    resp = kms.create_key(
        Policy=json.dumps(policy),
        KeySpec="SYMMETRIC_DEFAULT",
        KeyUsage="ENCRYPT_DECRYPT",
        Description=ctx.unique_name("sim2real-behav-cw-dataset-kms-race-"),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    key_arn = resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
