"""publish-topic-depth-limit-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-topic-depth-limit-rejected"
GROUP = 'publish-topic-validation'
SERVICES = ['iot-data']


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
_MAX_TOPIC_PARTS = 8


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


def _poll(fn, predicate, timeout_s: float = 30.0, interval_s: float = 1.0):
    """Poll fn() until predicate holds, tolerating transient exceptions; else AssertionError.

    Retained-message reads are read-your-write within ~0.07 s (measured, 5 samples, us-west-2), so
    this bound is generous by ~400x and a timeout is a real failure.
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
    """The MQTT topic depth limit is EXACTLY 8 levels: the 8th is accepted, the 9th is refused.

    The 256-byte topic ceiling is asserted too, each with its own InvalidRequestException message,
    because a topic past either limit is one no subscription filter can match.
    """
    iot_data = ctx.client("iot-data")
    base = ctx.unique_name("sim2real-behav-iotdata-depth-")

    at_limit = "/".join([base] + list("abcdefg"))          # 8 parts
    over_limit = "/".join([base] + list("abcdefgh"))       # 9 parts
    assert at_limit.count("/") + 1 == _MAX_TOPIC_PARTS, f"test bug: {at_limit!r}"
    assert over_limit.count("/") + 1 == _MAX_TOPIC_PARTS + 1, f"test bug: {over_limit!r}"

    # Control FIRST and at the boundary: the 8th level is legal, so a check that only saw the
    # refusal could not tell a correct limit from an emulator that refuses everything deep.
    iot_data.publish(topic=at_limit, payload=b"sim2real-behav-eight-levels", retain=True, qos=1)
    ctx.on_cleanup(lambda _t=at_limit: iot_data.publish(topic=_t, payload=b"", retain=True))
    landed = _poll(lambda: iot_data.get_retained_message(topic=at_limit),
                   lambda r: r["payload"] == b"sim2real-behav-eight-levels")
    assert landed["topic"] == at_limit, (
        f"a {_MAX_TOPIC_PARTS}-part topic is legal and must be retained under its own name, got "
        f"{landed['topic']!r}"
    )

    # Registered before the call, because a wrongly-accepted retained publish IS a resource.
    ctx.on_cleanup(lambda _t=over_limit: iot_data.publish(topic=_t, payload=b"", retain=True))
    code = _error_code(lambda: iot_data.publish(
        topic=over_limit, payload=b"sim2real-behav-nine-levels", retain=True, qos=1))
    assert code == "InvalidRequestException", (
        f"a {_MAX_TOPIC_PARTS + 1}-part topic must be refused with InvalidRequestException, got "
        f"{code!r} — the Smithy model declares no length or pattern on Topic, so this rule exists "
        f"only in the service"
    )
    message = _error_message(lambda: iot_data.publish(
        topic=over_limit, payload=b"sim2real-behav-nine-levels", retain=True, qos=1))
    assert message == f"Topic can't contain more than {_MAX_TOPIC_PARTS} parts", (
        f"the refusal must name the part limit, got {message!r}"
    )

    # Effect absent: nothing was stored for the refused topic.
    absent = _error_code(lambda: iot_data.get_retained_message(topic=over_limit))
    assert absent == "ResourceNotFoundException", (
        f"the refused publish must not have stored a retained message at {over_limit!r}, got "
        f"{absent!r}"
    )

    # The SECOND, independent ceiling: total byte length, well within the 8-part limit.
    long_topic = f"{base}/{'z' * 256}"
    assert long_topic.count("/") + 1 <= _MAX_TOPIC_PARTS, f"test bug: {long_topic!r}"
    assert len(long_topic.encode()) > 256, f"test bug: {len(long_topic.encode())} bytes"
    ctx.on_cleanup(lambda _t=long_topic: iot_data.publish(topic=_t, payload=b"", retain=True))
    long_code = _error_code(lambda: iot_data.publish(
        topic=long_topic, payload=b"sim2real-behav-too-long", retain=True, qos=1))
    assert long_code == "InvalidRequestException", (
        "a topic over 256 bytes must be refused even at legal depth, got "
        f"{long_code!r} — an emulator that only counts parts passes the depth assertion above and "
        f"fails here"
    )
    long_message = _error_message(lambda: iot_data.publish(
        topic=long_topic, payload=b"sim2real-behav-too-long", retain=True, qos=1))
    assert long_message == "Topic can't contain more than 256 bytes", (
        f"the byte-limit refusal must name the byte limit, got {long_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
