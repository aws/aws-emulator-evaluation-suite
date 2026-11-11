"""publish-oversize-payload-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-oversize-payload-rejected"
GROUP = 'publish-payload-validation'
SERVICES = ['iot-data']


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
_MAX_PAYLOAD_BYTES = 131072  # 128 KiB, measured as INCLUSIVE


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


def _poll(fn, predicate, timeout_s: float = 60.0, interval_s: float = 1.0):
    """Poll fn() until predicate holds, tolerating transient exceptions; else AssertionError.

    Retained reads are read-your-write within ~0.07 s (measured, us-west-2); the bound is
    deliberately far larger because this check moves a 128 KiB body each way.
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Publish's payload ceiling is INCLUSIVE at 131072 bytes: that size lands intact, one more is 413.

    131073 bytes is RequestEntityTooLargeException / HTTP 413 "payload larger than 131072 bytes";
    the at-limit payload must round-trip byte-identically, ruling out truncation at the boundary.
    """
    iot_data = ctx.client("iot-data")
    base = ctx.unique_name("sim2real-behav-iotdata-size-")
    at_limit_topic = f"{base}/atlimit"
    over_limit_topic = f"{base}/over"

    at_limit = b"P" * _MAX_PAYLOAD_BYTES
    over_limit = b"P" * (_MAX_PAYLOAD_BYTES + 1)
    assert len(at_limit) == _MAX_PAYLOAD_BYTES, f"test bug: {len(at_limit)}"

    # Control FIRST, exactly AT the ceiling, retained so the bytes are observable.
    iot_data.publish(topic=at_limit_topic, payload=at_limit, retain=True, qos=1)
    ctx.on_cleanup(lambda _t=at_limit_topic: iot_data.publish(topic=_t, payload=b"", retain=True))
    stored = _poll(lambda: iot_data.get_retained_message(topic=at_limit_topic),
                   lambda r: len(r["payload"]) == _MAX_PAYLOAD_BYTES)
    assert len(stored["payload"]) == _MAX_PAYLOAD_BYTES, (
        f"a payload of exactly {_MAX_PAYLOAD_BYTES} bytes is legal and must be stored whole, got "
        f"{len(stored['payload'])} bytes back"
    )
    assert stored["payload"] == at_limit, (
        "the at-limit payload must round-trip byte-identically — a length match with different "
        "bytes would be silent corruption at the boundary"
    )

    # Registered before the call: a wrongly-accepted retained publish IS a resource.
    ctx.on_cleanup(lambda _t=over_limit_topic: iot_data.publish(topic=_t, payload=b"", retain=True))
    code = _error_code(lambda: iot_data.publish(
        topic=over_limit_topic, payload=over_limit, retain=True, qos=1))
    assert code == "RequestEntityTooLargeException", (
        f"a payload of {len(over_limit)} bytes must be refused with "
        f"RequestEntityTooLargeException, got {code!r}. `Payload` is an unconstrained blob in the "
        f"Smithy model, so this ceiling exists only in the service."
    )
    message = _error_message(lambda: iot_data.publish(
        topic=over_limit_topic, payload=over_limit, retain=True, qos=1))
    assert message == f"payload larger than {_MAX_PAYLOAD_BYTES} bytes", (
        f"the refusal must name the byte ceiling, got {message!r}"
    )

    # Effect absent: nothing stored, not even a truncated copy.
    absent = _error_code(lambda: iot_data.get_retained_message(topic=over_limit_topic))
    assert absent == "ResourceNotFoundException", (
        "the refused publish must not have stored anything — a truncated retained message would "
        f"be the worst outcome of the three; got {absent!r}"
    )

    # And the at-limit message is still intact, i.e. the refusal did not disturb its sibling.
    intact = iot_data.get_retained_message(topic=at_limit_topic)
    assert len(intact["payload"]) == _MAX_PAYLOAD_BYTES, (
        f"the legal retained message must survive the refused publish, got "
        f"{len(intact['payload'])} bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
