"""retained-message-overwrite-keeps-latest."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "retained-message-overwrite-keeps-latest"
GROUP = 'retained-message'
SERVICES = ['iot-data']


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
def _poll(fn, predicate, timeout_s: float = 30.0, interval_s: float = 1.0):
    """Poll fn() until predicate holds, tolerating transient exceptions; else AssertionError.

    Retained reads are read-your-write within ~0.07 s (measured, 5 samples, us-west-2).
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


def _retained_summary(iot_data, topic: str) -> dict | None:
    """The ListRetainedMessages summary for one topic, paginating the whole account.

    ListRetainedMessages has no topic filter, so other retained messages in the account can
    push this topic off page one. maxResults would narrow
    the page without bounding it; the next-token loop is what actually bounds it.
    """
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        page = iot_data.list_retained_messages(**kwargs)
        for entry in page.get("retainedTopics", []):
            if entry["topic"] == topic:
                return entry
        token = page.get("nextToken") or None
        if not token:
            return None


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A retained topic holds exactly ONE message: a second retained publish REPLACES the first.

    GET returns the new payload and qos with an advancing ``lastModifiedTime``, and the listing's
    ``payloadSize`` reports the new length, so the store kept the latest value and not a history.
    """
    iot_data = ctx.client("iot-data")
    topic = f"{ctx.unique_name('sim2real-behav-iotdata-overwrite-')}/state"

    first_payload = b"sim2real-behav-first"
    second_payload = b"sim2real-behav-second-is-a-longer-payload"
    assert len(second_payload) != len(first_payload), "test bug: sizes must differ"

    iot_data.publish(topic=topic, payload=first_payload, retain=True, qos=1)
    ctx.on_cleanup(lambda _t=topic: iot_data.publish(topic=_t, payload=b"", retain=True))
    first = _poll(lambda: iot_data.get_retained_message(topic=topic),
                  lambda r: r["payload"] == first_payload)
    assert first["qos"] == 1, f"setup: expected qos 1, got {first.get('qos')!r}"

    first_summary = _retained_summary(iot_data, topic)
    assert first_summary is not None, (
        f"setup: {topic!r} must appear in ListRetainedMessages after a retained publish"
    )
    assert first_summary["payloadSize"] == len(first_payload), (
        f"setup: payloadSize should be {len(first_payload)}, got {first_summary['payloadSize']!r}"
    )

    # IoT stamps lastModifiedTime in MILLIseconds, so two back-to-back publishes could share a
    # stamp. Poll until the payload is the new one AND the stamp has strictly advanced, rather
    # than sleeping a guessed interval.
    iot_data.publish(topic=topic, payload=second_payload, retain=True, qos=0)
    second = _poll(
        lambda: iot_data.get_retained_message(topic=topic),
        lambda r: (r["payload"] == second_payload
                   and r["lastModifiedTime"] > first["lastModifiedTime"]),
    )

    assert second["payload"] == second_payload, (
        f"the retained message must be the LATEST publish, got {second['payload']!r}"
    )
    assert second["topic"] == topic, f"the topic must be echoed unchanged, got {second['topic']!r}"
    assert second["lastModifiedTime"] > first["lastModifiedTime"], (
        "lastModifiedTime must strictly advance on an overwrite; got "
        f"{second['lastModifiedTime']} after {first['lastModifiedTime']}"
    )
    assert second["qos"] == 0, (
        "qos must come from the surviving (latest) publish, not the original: expected 0, got "
        f"{second['qos']!r}"
    )

    # The listing is derived from the surviving message — this is what exposes a store that
    # kept both and merely serves the newest from GET.
    second_summary = _retained_summary(iot_data, topic)
    assert second_summary is not None, (
        f"{topic!r} disappeared from ListRetainedMessages after the overwrite"
    )
    assert second_summary["payloadSize"] == len(second_payload), (
        f"ListRetainedMessages payloadSize must report the surviving message's "
        f"{len(second_payload)} bytes, got {second_summary['payloadSize']!r} — "
        f"{len(first_payload)} would mean the first message is still the stored one"
    )
    assert second_summary["qos"] == 0, (
        f"the listing's qos must match the surviving message, got {second_summary['qos']!r}"
    )
    assert second_summary["lastModifiedTime"] == second["lastModifiedTime"], (
        "the listing and the read must describe the SAME stored message; got listing "
        f"{second_summary['lastModifiedTime']} vs read {second['lastModifiedTime']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
