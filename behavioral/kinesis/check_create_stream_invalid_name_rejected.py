"""create-stream-invalid-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-invalid-name-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _wait_active(c, name, timeout_s=150.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream {name!r} never reached ACTIVE within {timeout_s}s")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStream with a StreamName outside the documented `[a-zA-Z0-9_.-]+` pattern (a space
    and a '!') is rejected with ValidationException and creates nothing, while a syntactically
    valid name in an otherwise identical request succeeds."""
    c = ctx.client("kinesis")

    bad_name = "sim2real behav invalid!"
    code, message = _error(
        lambda: c.create_stream(StreamName=bad_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        f"1 validation error detected: Value '{bad_name}' at 'streamName' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    pages = c.get_paginator("list_streams").paginate()
    all_names = {name for page in pages for name in page["StreamNames"]}
    assert bad_name not in all_names, (
        f"the rejected CreateStream must not have created a stream named {bad_name!r}, "
        "but it appears in ListStreams"
    )

    good_name = ctx.unique_name("sim2real-behav-kds-")
    c.create_stream(StreamName=good_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=good_name, EnforceConsumerDeletion=True))
    _wait_active(c, good_name)
    summary = c.describe_stream_summary(StreamName=good_name)["StreamDescriptionSummary"]
    assert summary["StreamName"] == good_name, (
        f"expected the valid-name control to create {good_name!r}, describe returned "
        f"{summary['StreamName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
