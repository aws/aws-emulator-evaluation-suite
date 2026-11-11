"""retained-message-binary-payload-byte-equality."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "retained-message-binary-payload-byte-equality"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publishing a retained message with a raw binary (non-UTF8) payload and reading it
    back via GetRetainedMessage yields byte-identical content -- not re-encoded,
    UTF-8-coerced, or truncated data."""
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    iot_data = ctx.client("iot-data", endpoint_url=ctx.endpoint_url(endpoint))

    topic = ctx.unique_name("sim2real/retained/binary/")
    # deliberately include bytes that are invalid UTF-8 sequences (0xc0/0xc1/0xf5 are
    # never valid lead bytes) to catch any accidental UTF-8 re-encoding/coercion
    payload = bytes(range(256)) + "π§Ω".encode("utf-8") + b"\xc0\xc1\xf5\x00\xff"

    iot_data.publish(topic=topic, qos=1, payload=payload, retain=True)
    ctx.on_cleanup(lambda: iot_data.publish(topic=topic, qos=1, payload=b"", retain=True))

    retained = _poll_until(
        lambda: _get_retained(iot_data, topic),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=1.0,
    )
    assert retained["payload"] == payload, (
        f"GetRetainedMessage returned {len(retained['payload'])} bytes "
        f"({retained['payload'][:32]!r}...), published {len(payload)} bytes ({payload[:32]!r}...)"
    )
    assert retained["topic"] == topic, f"expected topic {topic!r}, got {retained['topic']!r}"


def _get_retained(iot_data, topic):
    from botocore.exceptions import ClientError
    try:
        return iot_data.get_retained_message(topic=topic)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise AssertionError(f"condition never became true within {timeout_s}s; last value: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
