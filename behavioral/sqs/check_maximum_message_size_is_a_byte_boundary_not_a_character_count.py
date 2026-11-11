"""maximum-message-size-is-a-byte-boundary-not-a-character-count."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maximum-message-size-is-a-byte-boundary-not-a-character-count"
GROUP = "errors"
SERVICES = ["sqs"]

_TOO_LONG_MESSAGE = "One or more parameters are invalid. Reason: Message must be shorter than {limit} bytes."

# 1024 is the MINIMUM legal MaximumMessageSize, the cheapest value at which to probe the boundary.
_LIMIT_BYTES = 1024
_RAISED_LIMIT_BYTES = 4096
_PROPAGATE_S = 90.0  # attribute changes can take up to 60s to propagate (documented)
# U+00E9 LATIN SMALL LETTER E WITH ACUTE: exactly 2 bytes in UTF-8, 1 Python character. The whole
# point of the multi-byte leg is that len(str) and len(str.encode("utf-8")) disagree by 2x.
_TWO_BYTE_CHAR = "é"

_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "max-message-size-bytes",
}


def _client_error(fn):
    """Return the botocore Error dict; raise if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("the call succeeded, but this leg exists because it must be rejected")


def _drain_bodies(sqs, url, *, expected_n, timeout_s):
    """Receive-and-delete until `expected_n` distinct messages are seen; return their bodies.

    Raises on the deadline so an under-delivery fails rather than returning a short set.
    """
    seen: dict[str, str] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(seen) < expected_n:
        for msg in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        ).get("Messages", []):
            seen[msg["MessageId"]] = msg["Body"]
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    assert len(seen) == expected_n, (
        f"expected exactly {expected_n} message(s) on the queue within {timeout_s}s, drained "
        f"{len(seen)}: {[len(b.encode('utf-8')) for b in seen.values()]} byte-lengths"
    )
    return set(seen.values())


def _send_ok(sqs, url, body, *, why):
    resp = sqs.send_message(QueueUrl=url, MessageBody=body)
    assert resp.get("MessageId"), (
        f"{why}: SendMessage returned no MessageId for a {len(body.encode('utf-8'))}-byte body; "
        f"response keys {sorted(resp)}"
    )
    return resp


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """MaximumMessageSize is an inclusive UTF-8 BYTE limit: at-limit bodies pass, one byte or one
    2-byte character over is refused, and raising the limit admits the identical body byte-exact.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html"""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"MaximumMessageSize": str(_LIMIT_BYTES)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # The limit under test is read back off the target, not assumed.
    reported = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["MaximumMessageSize"])[
        "Attributes"
    ]["MaximumMessageSize"]
    assert reported == str(_LIMIT_BYTES), (
        f"the queue reports MaximumMessageSize={reported!r}, not {_LIMIT_BYTES}; every boundary "
        f"assertion below would be probing the wrong limit"
    )
    limit = int(reported)

    ascii_at_limit = "a" * limit
    ascii_over_by_one = "a" * (limit + 1)
    multibyte_at_limit = _TWO_BYTE_CHAR * (limit // 2)
    multibyte_over_by_one = _TWO_BYTE_CHAR * (limit // 2 + 1)

    # Sanity on the fixtures themselves: the multi-byte pair is the whole point, so if the encoding
    # assumption is broken locally the check must say so rather than assert something else.
    assert len(ascii_at_limit.encode("utf-8")) == limit, "ASCII fixture is not exactly at the limit"
    assert len(multibyte_at_limit.encode("utf-8")) == limit, (
        f"the multi-byte at-limit fixture encodes to "
        f"{len(multibyte_at_limit.encode('utf-8'))} bytes, expected {limit}"
    )
    assert len(multibyte_over_by_one) <= limit, (
        f"the over-limit multi-byte fixture is {len(multibyte_over_by_one)} CHARACTERS, which must "
        f"stay under the {limit}-byte limit for the leg to discriminate byte- from "
        f"character-counting"
    )
    assert len(multibyte_over_by_one.encode("utf-8")) == limit + 2, (
        f"the over-limit multi-byte fixture encodes to "
        f"{len(multibyte_over_by_one.encode('utf-8'))} bytes, expected {limit + 2}"
    )

    # --- positive control: both at-limit bodies are accepted --------------------------
    _send_ok(sqs, url, ascii_at_limit, why="an ASCII body of exactly MaximumMessageSize bytes")
    _send_ok(
        sqs,
        url,
        multibyte_at_limit,
        why=(
            f"a {len(multibyte_at_limit)}-character body that encodes to exactly "
            f"{limit} UTF-8 bytes"
        ),
    )

    # --- break exactly one thing: one byte over ---------------------------------------
    error = _client_error(lambda: sqs.send_message(QueueUrl=url, MessageBody=ascii_over_by_one))
    assert error.get("Code") == "InvalidParameterValue", (
        f"a {limit + 1}-byte body (one byte over MaximumMessageSize={limit}) was rejected with "
        f"{error.get('Code')!r}, expected 'InvalidParameterValue'"
    )
    expected_message = _TOO_LONG_MESSAGE.format(limit=limit)
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # --- and the encoding leg: one 2-byte character over, well under the CHARACTER limit
    error = _client_error(lambda: sqs.send_message(QueueUrl=url, MessageBody=multibyte_over_by_one))
    assert error.get("Code") == "InvalidParameterValue", (
        f"a {len(multibyte_over_by_one)}-character body encoding to "
        f"{len(multibyte_over_by_one.encode('utf-8'))} UTF-8 bytes was rejected with "
        f"{error.get('Code')!r}, expected 'InvalidParameterValue'. MaximumMessageSize={limit} is "
        f"a BYTE limit, so a body far under {limit} characters can still exceed it"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # --- effect absent: exactly the two accepted bodies are on the queue --------------
    drained = _drain_bodies(sqs, url, expected_n=2, timeout_s=20.0)
    assert drained == {ascii_at_limit, multibyte_at_limit}, (
        f"the queue's delivered set is not exactly the two accepted bodies: got byte-lengths "
        f"{sorted(len(b.encode('utf-8')) for b in drained)}, expected "
        f"[{limit}, {limit}]. A rejected body that lands anyway, or an accepted body that arrives "
        f"truncated, both show up here"
    )

    # --- restore: raise the limit, and the IDENTICAL rejected call must now succeed ---
    sqs.set_queue_attributes(
        QueueUrl=url, Attributes={"MaximumMessageSize": str(_RAISED_LIMIT_BYTES)}
    )
    deadline = time.monotonic() + _PROPAGATE_S
    last_error = None
    accepted = False
    while time.monotonic() < deadline:
        try:
            sqs.send_message(QueueUrl=url, MessageBody=multibyte_over_by_one)
        except ClientError as exc:
            # Only the pre-propagation rejection is tolerated here; the loop's deadline turns a
            # permanent rejection into a FAILURE below rather than a silent pass.
            last_error = exc.response["Error"]["Code"]
            time.sleep(2.0)
            continue
        accepted = True
        break
    assert accepted, (
        f"after raising MaximumMessageSize to {_RAISED_LIMIT_BYTES}, the identical "
        f"{len(multibyte_over_by_one.encode('utf-8'))}-byte body was still rejected "
        f"({last_error!r}) throughout {_PROPAGATE_S}s -- the attribute is not consulted per send"
    )
    restored = _drain_bodies(sqs, url, expected_n=1, timeout_s=20.0)
    assert restored == {multibyte_over_by_one}, (
        f"after the limit was raised, the queue delivered {sorted(len(b) for b in restored)} "
        f"character-length(s) instead of the one {len(multibyte_over_by_one)}-character body; the "
        f"body must arrive byte-identical, not truncated to the old limit"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
