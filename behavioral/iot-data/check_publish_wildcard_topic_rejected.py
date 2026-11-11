"""publish-wildcard-topic-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-wildcard-topic-rejected"
GROUP = 'publish-topic-validation'
SERVICES = ['iot-data']


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
def _error_code(fn):
    """Call fn(); return the botocore Error.Code, or a sentinel if it unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "<<CALL UNEXPECTEDLY SUCCEEDED>>"


def _error_message(fn):
    """Call fn(); return the botocore Error.Message, or a sentinel if it SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Message")
    return "<<CALL UNEXPECTEDLY SUCCEEDED>>"


def _topic_in_listing(iot_data, topic: str) -> bool:
    """Whether one topic appears anywhere in ListRetainedMessages, paginating the account.

    This operation has no topic filter, so other retained messages in the account can push this
    topic off page one; the next-token loop is what bounds the answer. It is also the only way to
    assert the ABSENCE of a retained message under an illegal topic name, since GetRetainedMessage
    refuses to be asked about one at all (measured below).
    """
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        page = iot_data.list_retained_messages(**kwargs)
        if any(entry["topic"] == topic for entry in page.get("retainedTopics", [])):
            return True
        token = page.get("nextToken") or None
        if not token:
            return False


def _poll(fn, predicate, timeout_s: float = 30.0, interval_s: float = 1.0):
    """Poll fn() until predicate holds, tolerating transient exceptions; else AssertionError.

    Retained-message writes are read-your-write in well under a second (measured: 5 samples,
    0.06-0.08 s in us-west-2), so this bound is ~400x the observed latency and a timeout here is
    a real failure rather than an impatient poll.
    """
    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient read-after-write
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An MQTT SUBSCRIPTION wildcard is not a publish target, and must not fan out to matches.

    ``#`` and ``+`` are refused "Invalid topic filter"; the refused publish stores nothing under the
    wildcard name and leaves the retained message at a matching topic intact.
    """
    iot_data = ctx.client("iot-data")
    base = ctx.unique_name("sim2real-behav-iotdata-wild-")
    leaf = f"{base}/leaf"
    wildcard = f"{base}/#"
    control = f"{base}/control"

    # A retained message at a topic the wildcard WOULD match, so a fan-out is observable.
    iot_data.publish(topic=leaf, payload=b"sim2real-behav-leaf-original", retain=True, qos=1)
    ctx.on_cleanup(lambda _t=leaf: iot_data.publish(topic=_t, payload=b"", retain=True))
    _poll(lambda: iot_data.get_retained_message(topic=leaf),
          lambda r: r["payload"] == b"sim2real-behav-leaf-original")

    # A retained publish is used for the refused call too: had AWS accepted it, the resource
    # would exist, so cleanup is registered BEFORE the call rather than after the assert.
    ctx.on_cleanup(lambda _t=wildcard: iot_data.publish(topic=_t, payload=b"", retain=True))
    code = _error_code(lambda: iot_data.publish(
        topic=wildcard, payload=b"sim2real-behav-wildcard-overwrite", retain=True, qos=1))
    assert code == "InvalidRequestException", (
        f"publishing to the wildcard topic {wildcard!r} must be refused with "
        f"InvalidRequestException, got {code!r}"
    )
    message = _error_message(lambda: iot_data.publish(
        topic=wildcard, payload=b"sim2real-behav-wildcard-overwrite", retain=True, qos=1))
    assert message == "Invalid topic filter", (
        f"expected the refusal message 'Invalid topic filter', got {message!r}"
    )

    # Effect absent (1): no fan-out — the matching leaf still holds its original payload.
    still = iot_data.get_retained_message(topic=leaf)
    assert still["payload"] == b"sim2real-behav-leaf-original", (
        "the refused wildcard publish must not have reached the topic the wildcard matches; "
        f"{leaf!r} now holds {still['payload']!r}. An emulator treating '#' as it means on "
        f"SUBSCRIBE rewrites a whole subtree of device state in one call."
    )

    # Effect absent (2): nothing stored under the literal wildcard string either. This has to be
    # asserted through the LISTING, because the read path refuses the name as well (below) — so
    # "GetRetainedMessage says 404" is not available as the absence proof here.
    assert not _topic_in_listing(iot_data, wildcard), (
        f"no retained message may exist under the literal wildcard name {wildcard!r}, but it "
        f"appears in ListRetainedMessages — a retained message stored under a literal '#' matches "
        f"no subscription and is invisible to every reader"
    )

    # And the validation is SYMMETRIC: GetRetainedMessage refuses the same name rather than
    # answering not-found, so a wildcard is never a legal topic identity on either path.
    # AWS answers 400 InvalidRequestException "Invalid topic filter", where a plain absent topic
    # gives 404 ResourceNotFoundException "Retained message not found"; a 404 here would treat the
    # wildcard as a well-formed topic name with no value.
    read_code = _error_code(lambda: iot_data.get_retained_message(topic=wildcard))
    assert read_code == "InvalidRequestException", (
        f"GetRetainedMessage must refuse the wildcard topic {wildcard!r} as malformed rather than "
        f"report it absent, got {read_code!r}"
    )
    read_message = _error_message(lambda: iot_data.get_retained_message(topic=wildcard))
    assert read_message == "Invalid topic filter", (
        f"the read-path refusal must be the same 'Invalid topic filter', got {read_message!r}"
    )

    # The contrast that makes the line above meaningful: a legal-but-absent sibling topic is a
    # not-found, not a validation error.
    missing_code = _error_code(lambda: iot_data.get_retained_message(topic=f"{base}/never"))
    assert missing_code == "ResourceNotFoundException", (
        "a legal topic with no retained message must be ResourceNotFoundException, not a "
        f"validation error, got {missing_code!r}"
    )

    # Control, in the same file: an ordinary sibling topic still accepts a retained publish.
    iot_data.publish(topic=control, payload=b"sim2real-behav-control-ok", retain=True, qos=1)
    ctx.on_cleanup(lambda _t=control: iot_data.publish(topic=_t, payload=b"", retain=True))
    got = _poll(lambda: iot_data.get_retained_message(topic=control),
                lambda r: r["payload"] == b"sim2real-behav-control-ok")
    assert got["topic"] == control, (
        f"the control publish must be retained under its own topic, got {got['topic']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
