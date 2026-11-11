"""publish-to-topic-whose-key-is-pending-deletion-fails-kms-invalid-state."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-to-topic-whose-key-is-pending-deletion-fails-kms-invalid-state"
GROUP = "kms-state"
SERVICES = ["sns"]

#: SNS reuses a topic's data key for a while, so a key-state change can take minutes to reach
#: Publish (observed at about five minutes).
_KEY_STATE_CEILING_S = 420

# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html
@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Publish to an SSE-KMS topic follows its key's live state: KMSInvalidState once the key is
    pending deletion, KMSDisabled after the deletion is cancelled (key left Disabled), and success
    again once the key is enabled; a Publish before scheduling deletion is the positive control."""
    sns = ctx.client("sns")
    kms = ctx.client("kms")

    key_id = kms.create_key(Description=f"sim2real-behav-sns {CHECK}",
                            Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _schedule_deletion(kms, key_id))
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-kmspend-"),
                                 Attributes={"KmsMasterKeyId": key_id},
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    assert sns.publish(TopicArn=topic_arn, Message="sim2real-before")["MessageId"], (
        "control: Publish must succeed while the key is Enabled")

    kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "PendingDeletion", f"the scheduled key reports KeyState {state!r}"
    code, message = _refusal_once_settled(sns, topic_arn, "KMSInvalidState")
    expected = _relayed(f"{key_arn} is pending deletion.", "KMSInvalidStateException", message)
    assert (code, message) == ("KMSInvalidState", expected), (
        f"Publish while the key is pending deletion must fail KMSInvalidState {expected!r}; "
        f"got {code!r} {message!r}"
    )

    kms.cancel_key_deletion(KeyId=key_id)
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"a key whose deletion was cancelled must be Disabled, got {state!r}"
    code, message = _refusal_once_settled(sns, topic_arn, "KMSDisabled")
    expected = _relayed(f"{key_arn} is disabled.", "DisabledException", message)
    assert (code, message) == ("KMSDisabled", expected), (
        f"Publish after the deletion is cancelled (key Disabled) must fail KMSDisabled "
        f"{expected!r}; got {code!r} {message!r}"
    )

    kms.enable_key(KeyId=key_id)
    deadline = time.monotonic() + _KEY_STATE_CEILING_S
    while True:
        try:
            mid = sns.publish(TopicArn=topic_arn, Message="sim2real-after")["MessageId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KMSDisabled" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    assert mid, "Publish must succeed again once the key is re-enabled"


def _schedule_deletion(kms, key_id: str) -> None:
    if kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] != "PendingDeletion":
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)


def _refusal_once_settled(sns, topic_arn: str, want: str) -> tuple[str | None, str | None]:
    """Publish until the refusal code is ``want`` or a bounded deadline passes, then return the
    last (code, message). Key-state changes reach the publish path asynchronously; any other
    outcome on the deadline is returned for the caller to assert on."""
    deadline = time.monotonic() + _KEY_STATE_CEILING_S
    while True:
        try:
            sns.publish(TopicArn=topic_arn, Message="sim2real-probe")
            got: tuple[str | None, str | None] = ("<succeeded>", None)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message"))
        if got[0] == want or time.monotonic() > deadline:
            return got
        time.sleep(2)


def _relayed(text: str, kms_code: str, actual: str | None) -> str:
    """The exact message SNS relays from KMS. The KMS request id is the only per-call token;
    it is taken from the actual text and must parse as a UUID."""
    _, _, tail = (actual or "").partition("; Request ID: ")
    request_id = tail[:36]
    try:
        uuid.UUID(request_id)
    except ValueError:
        request_id = "<a KMS request id>"
    return (f"{text} (Service: AWSKMS; Status Code: 400; Error Code: {kms_code}; "
            f"Request ID: {request_id}; Proxy: null)")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
