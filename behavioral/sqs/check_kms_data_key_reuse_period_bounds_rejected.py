"""kms-data-key-reuse-period-bounds-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kms-data-key-reuse-period-bounds-rejected"
GROUP = "server-side"
SERVICES = ["sqs"]

_INVALID_MESSAGE = "Invalid value for the parameter KmsDataKeyReusePeriodSeconds."


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: an out-of-range reuse period that is accepted must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _reuse(sqs, url) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["KmsDataKeyReusePeriodSeconds"])[
        "Attributes"
    ]["KmsDataKeyReusePeriodSeconds"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """KmsDataKeyReusePeriodSeconds on an SSE-KMS queue accepts only 60..86400 (default 300): 59,
    86401 and "abc" are refused InvalidAttributeValue leaving the stored value, CreateQueue with 59
    creates no queue, and messages round-trip at each accepted boundary."""
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")
    name = ctx.unique_name("sim2real-behav-reuse-")
    key_id = kms.create_key(
        Description=name, Tags=[{"TagKey": "sim2real", "TagValue": name}]
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    url = sqs.create_queue(QueueName=name, Attributes={"KmsMasterKeyId": key_id})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    assert _reuse(sqs, url) == "300", f"default KmsDataKeyReusePeriodSeconds was {_reuse(sqs, url)!r}"

    refused_name = name + "-refused"
    err = _error(
        lambda: sqs.create_queue(
            QueueName=refused_name,
            Attributes={"KmsMasterKeyId": key_id, "KmsDataKeyReusePeriodSeconds": "59"},
        )
    )
    assert (err.get("Code"), err.get("Message")) == ("InvalidAttributeValue", _INVALID_MESSAGE), (
        f"CreateQueue with KmsDataKeyReusePeriodSeconds=59 gave {err!r}"
    )
    err = _error(lambda: sqs.get_queue_url(QueueName=refused_name))
    assert err.get("Code") == "AWS.SimpleQueueService.NonExistentQueue", (
        f"the refused CreateQueue must leave no queue behind; GetQueueUrl gave {err!r}"
    )

    stored = "300"
    for value, legal in (("59", False), ("60", True), ("86401", False), ("86400", True), ("abc", False)):
        if legal:
            sqs.set_queue_attributes(QueueUrl=url, Attributes={"KmsDataKeyReusePeriodSeconds": value})
            stored = value
            deadline = time.monotonic() + 60
            while _reuse(sqs, url) != value and time.monotonic() < deadline:
                time.sleep(1)
            body = f"encrypted-with-reuse-{value}"
            sqs.send_message(QueueUrl=url, MessageBody=body)
            got = None
            recv_deadline = time.monotonic() + 30
            while got is None and time.monotonic() < recv_deadline:
                msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
                if msgs:
                    got = msgs[0]
            assert got is not None and got["Body"] == body, (
                f"with KmsDataKeyReusePeriodSeconds={value} the encrypted queue must round-trip a "
                f"message; received {got and got['Body']!r}"
            )
            sqs.delete_message(QueueUrl=url, ReceiptHandle=got["ReceiptHandle"])
        else:
            err = _error(
                lambda value=value: sqs.set_queue_attributes(
                    QueueUrl=url, Attributes={"KmsDataKeyReusePeriodSeconds": value}
                )
            )
            assert (err.get("Code"), err.get("Message")) == ("InvalidAttributeValue", _INVALID_MESSAGE), (
                f"KmsDataKeyReusePeriodSeconds={value!r} gave {err!r}"
            )
        assert _reuse(sqs, url) == stored, (
            f"after setting {value!r} the stored period is {_reuse(sqs, url)!r}, expected {stored!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
