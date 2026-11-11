"""retained-message-requires-retain-flag."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retained-message-requires-retain-flag"
GROUP = 'retained-message'
SERVICES = ['iot-data']


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message), or a sentinel pair if it
    unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "<<CALL UNEXPECTEDLY SUCCEEDED>>", None


def _poll(fn, predicate, timeout_s: float = 30.0, interval_s: float = 1.0):
    """Poll fn() until predicate holds, tolerating transient exceptions; else AssertionError."""
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


def _topic_in_listing(iot_data, topic: str) -> bool:
    """Whether one topic appears anywhere in ListRetainedMessages, paginating the account.

    No topic filter exists on this operation, so other retained messages in the account can
    push this topic off page one; the next-token loop is what bounds the search.
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


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Retention is OPT-IN per publish, and a non-retained publish neither stores nor clears.

    A readable retained control proves the store caught up, so the non-retained topic's absence is
    real; a non-retained publish over a retained topic leaves the retained copy untouched.
    """
    iot_data = ctx.client("iot-data")
    base = ctx.unique_name("sim2real-behav-iotdata-retainflag-")
    plain_topic = f"{base}/plain"
    kept_topic = f"{base}/kept"

    # A publish with no retain flag. Registered for cleanup first: if the target wrongly RETAINS
    # it, the resource exists and the assertions below must not abort before it can be reaped.
    ctx.on_cleanup(lambda _t=plain_topic: iot_data.publish(topic=_t, payload=b"", retain=True))
    iot_data.publish(topic=plain_topic, payload=b"sim2real-behav-not-retained", qos=1)

    # The clock: a RETAINED publish issued after the plain one. Once this is readable the store
    # has caught up past the plain publish, so the absence asserted next is a real absence.
    iot_data.publish(topic=kept_topic, payload=b"sim2real-behav-kept", retain=True, qos=1)
    ctx.on_cleanup(lambda _t=kept_topic: iot_data.publish(topic=_t, payload=b"", retain=True))
    kept = _poll(lambda: iot_data.get_retained_message(topic=kept_topic),
                 lambda r: r["payload"] == b"sim2real-behav-kept")
    assert kept["topic"] == kept_topic, f"control: got {kept['topic']!r}"

    # Effect absent (1): the non-retained publish stored nothing, by either read path.
    plain, plain_message = _error(lambda: iot_data.get_retained_message(topic=plain_topic))
    assert plain == "ResourceNotFoundException", (
        f"a publish without retain=true must not create a retained message at {plain_topic!r}, "
        f"got {plain!r} — an emulator that retains every publish turns the store into a log of "
        f"all traffic"
    )
    assert plain_message == "Retained message not found", plain_message
    assert not _topic_in_listing(iot_data, plain_topic), (
        f"{plain_topic!r} must not appear in ListRetainedMessages after a non-retained publish"
    )

    # The mirror-image rule: an ordinary publish across a retained topic must not clear it.
    iot_data.publish(topic=kept_topic, payload=b"sim2real-behav-transient", qos=0)
    # Synchronise on a second retained write to a THIRD topic rather than sleeping: once that is
    # readable, the store has processed the transient publish above.
    probe_topic = f"{base}/probe"
    iot_data.publish(topic=probe_topic, payload=b"sim2real-behav-probe", retain=True, qos=1)
    ctx.on_cleanup(lambda _t=probe_topic: iot_data.publish(topic=_t, payload=b"", retain=True))
    _poll(lambda: iot_data.get_retained_message(topic=probe_topic),
          lambda r: r["payload"] == b"sim2real-behav-probe")

    # Effect absent (2): the retained value survived the ordinary publish, byte-for-byte.
    survivor = iot_data.get_retained_message(topic=kept_topic)
    assert survivor["payload"] == b"sim2real-behav-kept", (
        "a publish without retain=true must not replace or clear the topic's retained message; "
        f"{kept_topic!r} now holds {survivor['payload']!r}. Only an empty retained payload clears."
    )
    assert survivor["lastModifiedTime"] == kept["lastModifiedTime"], (
        "the retained message was not rewritten, so its lastModifiedTime must be unchanged; got "
        f"{survivor['lastModifiedTime']} was {kept['lastModifiedTime']}"
    )

    # Control, in the same file: the documented clear DOES work on that same topic, so the
    # absences above are about the retain flag and not about a store that never accepts writes.
    iot_data.publish(topic=kept_topic, payload=b"", retain=True)
    cleared, cleared_message = _poll(
        lambda: _error(lambda: iot_data.get_retained_message(topic=kept_topic)),
        lambda err: err[0] == "ResourceNotFoundException")
    assert cleared == "ResourceNotFoundException", (
        f"an empty retained payload must clear the retained message, got {cleared!r}"
    )
    assert cleared_message == "Retained message not found", cleared_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
