"""publish-response-topic-wildcard-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-response-topic-wildcard-rejected"
GROUP = "publish-topic-validation"
SERVICES = ["iot-data"]


# `ctx.client("iot-data")` with no endpoint override resolves data-ats.iot.<region>.amazonaws.com,
# which serves every iot-data operation.
def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Publish whose responseTopic carries an MQTT wildcard is refused, and the refusal
    stores nothing under the publish topic; a responseTopic with no wildcard is accepted.
    """
    iot_data = ctx.client("iot-data")
    base = ctx.unique_name("sim2real-behav-iotdata-rtwild-")
    control_topic = f"{base}/control"
    refused_topic = f"{base}/refused"

    # Positive control: an ordinary responseTopic is accepted and the publish is retained.
    ctx.on_cleanup(lambda: iot_data.publish(topic=control_topic, payload=b"", retain=True))
    iot_data.publish(
        topic=control_topic, payload=b"sim2real-behav-control", retain=True, qos=1,
        responseTopic=f"{base}/control/response",
    )
    control = _poll(
        lambda: iot_data.get_retained_message(topic=control_topic),
        lambda r: r["payload"] == b"sim2real-behav-control",
    )
    assert control["topic"] == control_topic, f"control: got {control['topic']!r}"

    # The refused call also uses retain=True, so cleanup is registered BEFORE the call: had AWS
    # wrongly accepted it, the resource would exist and must still be reaped.
    ctx.on_cleanup(lambda: iot_data.publish(topic=refused_topic, payload=b"", retain=True))
    code, message = _error(lambda: iot_data.publish(
        topic=refused_topic, payload=b"sim2real-behav-refused", retain=True, qos=1,
        responseTopic=f"{base}/refused/response#",
    ))
    assert code == "InvalidRequestException", (
        f"a responseTopic carrying a wildcard must be refused with InvalidRequestException, "
        f"got {code!r}"
    )
    expected_message = (
        "This response topic isn't valid. Response topics must not contain MQTT wildcard "
        "characters (+ or #)"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the refused publish stored nothing under its own topic.
    absent_code, absent_message = _error(
        lambda: iot_data.get_retained_message(topic=refused_topic)
    )
    assert absent_code == "ResourceNotFoundException", (
        f"the refused publish must not have created a retained message at {refused_topic!r}, "
        f"got {absent_code!r}"
    )
    assert absent_message == "Retained message not found", absent_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
