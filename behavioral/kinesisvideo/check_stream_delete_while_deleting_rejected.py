"""stream-delete-while-deleting-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-delete-while-deleting-rejected"
GROUP = "state-machine"
SERVICES = ["kinesisvideo"]

#: The code ``_outcome`` reports for a call the target accepted.
_ACCEPTED = "<accepted>"

#: Fresh streams tried before the check gives up on observing the DELETING window.
_ATTEMPTS = 5
#: Bound on each wait for a stream to settle; the runner's remaining time bounds it further.
_SETTLE_TIMEOUT_S = 300.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Once DeleteStream is accepted the stream describes as DELETING, keeping its media type,
    retention, device name and default KMS key, until it is gone, and a second DeleteStream in that
    window is refused with ResourceInUseException (not active)."""
    kv = ctx.client("kinesisvideo")
    tried = []
    seen_deleting = refused = False
    for _ in range(_ATTEMPTS):
        name = ctx.unique_name("sim2real-kvs-deldel-")
        device = f"{name}-device"
        arn = kv.create_stream(StreamName=name, MediaType="video/h264", DataRetentionInHours=0,
                               DeviceName=device, Tags={"sim2real": CHECK})["StreamARN"]
        ctx.on_cleanup(lambda n=name, a=arn: _drop(kv, n, a))
        info = _settle(ctx, kv, name)
        assert info is not None and info["Status"] == "ACTIVE", (
            f"stream {name} settled {info and info['Status']!r}, expected 'ACTIVE'"
        )
        kv.delete_stream(StreamARN=arn, CurrentVersion=info["Version"])

        described = _describe(kv, name)
        if described is None:
            tried.append(f"{name}: gone before DescribeStream read it")
            continue
        assert described["Status"] == "DELETING", (
            f"DescribeStream right after an accepted DeleteStream reported {described['Status']!r}, "
            "expected 'DELETING'"
        )
        assert (described["StreamName"], described["StreamARN"]) == (name, arn), (
            f"DescribeStream of the deleting stream named {described['StreamName']!r} {described['StreamARN']!r}"
        )
        kept = tuple(described.get(k) for k in ("MediaType", "DataRetentionInHours", "DeviceName"))
        assert kept == ("video/h264", 0, device), (
            f"the DELETING stream describes MediaType, DataRetentionInHours, DeviceName {kept!r}, "
            f"expected ('video/h264', 0, {device!r})"
        )
        assert str(described.get("KmsKeyId")).endswith(":alias/aws/kinesisvideo"), (
            f"the DELETING stream describes KmsKeyId {described.get('KmsKeyId')!r}, expected the "
            "default alias/aws/kinesisvideo key"
        )
        seen_deleting = True

        code, message = _outcome(lambda: kv.delete_stream(StreamARN=arn))
        if (code, message) == ("ResourceInUseException", "The requested stream is not active."):
            refused = True
            break
        assert (code, message) == ("ResourceNotFoundException",
                                   "The requested stream is not found or not active."), (
            f"a second DeleteStream on a DELETING stream answered {code!r} {message!r}, expected "
            "ResourceInUseException 'The requested stream is not active.'"
        )
        tried.append(f"{name}: gone before the second DeleteStream")
    assert seen_deleting and refused, (
        f"never saw a DELETING stream refuse a second DeleteStream in {_ATTEMPTS} streams: {tried!r}"
    )


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, repr of the answer) when the
    target accepts the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


def _describe(kv, name: str) -> dict | None:
    try:
        return kv.describe_stream(StreamName=name)["StreamInfo"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _settle(ctx, kv, name: str) -> dict | None:
    """Poll until the stream leaves CREATING; returns its description, or None once gone."""
    left = ctx.time_left()
    timeout = _SETTLE_TIMEOUT_S if left is None else max(1.0, min(_SETTLE_TIMEOUT_S, left - min(60.0, left / 4)))
    deadline = time.monotonic() + timeout
    info = _describe(kv, name)
    while info is not None and info["Status"] == "CREATING":
        if time.monotonic() >= deadline:
            raise AssertionError(f"stream {name} still CREATING after {timeout:.0f}s")
        time.sleep(2)
        info = _describe(kv, name)
    return info


def _drop(kv, name: str, arn: str, timeout_s: float = 300.0) -> None:
    """Delete the stream once it is ACTIVE and wait until DescribeStream no longer finds it; a
    stream already gone counts as deleted."""
    deadline = time.monotonic() + timeout_s
    while True:
        info = _describe(kv, name)
        if info is None:
            return
        if info["Status"] == "ACTIVE":
            try:
                kv.delete_stream(StreamARN=arn)
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stream {name} still {info['Status']!r} after {timeout_s:.0f}s; not deleted"
            )
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
