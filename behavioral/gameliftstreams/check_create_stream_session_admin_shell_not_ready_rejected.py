"""create-stream-session-admin-shell-not-ready-rejected."""
from __future__ import annotations

import asyncio
import json
import time

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "create-stream-session-admin-shell-not-ready-rejected"
GROUP = "error-semantics"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStreamSessionAdminShell succeeds on a session in the documented eligible-status
    set and, once that session is TERMINATED, the identical call is rejected with the exact
    ValidationException naming that set."""
    try:
        import aiortc  # noqa: F401
    except ImportError as exc:
        raise RequiredToolMissing(['aiortc']) from exc

    s3 = ctx.client("s3")
    gls = ctx.client("gameliftstreams")

    app = _create_ready_application(ctx, gls, s3, script_body=b"#!/bin/sh\nsleep 3600\n")
    group = _create_active_stream_group(
        ctx, gls, location_configurations=[{"LocationName": ctx.region, "MaximumCapacity": 12}]
    )
    _wait_location_active(ctx, gls, group["Arn"])
    gls.associate_applications(Identifier=group["Arn"], ApplicationIdentifiers=[app["Id"]])

    session_arn = asyncio.run(_start_via_webrtc(gls, group["Arn"], app["Id"]))
    ctx.on_cleanup(
        lambda: _terminate_and_wait(gls, group["Arn"], session_arn)
    )

    # Positive control: once the session reaches an eligible status, the call succeeds.
    # CreateStreamSessionAdminShell's own StreamSessionAccessNotReadyException ("the terminal
    # connection is not yet available") covers a narrower, transient window inside that status
    # set -- if real AWS exposes it here, each occurrence's message must still be internally
    # consistent before the call finally succeeds.
    ready = _wait_session_admin_shell_eligible(gls, group["Arn"], session_arn)
    shell, not_ready_seen = _create_admin_shell_until_ready(gls, group["Arn"], session_arn)
    assert shell.get("SessionId"), (
        f"admin shell response missing SessionId once session reached "
        f"{ready['Status']}: {shell!r}"
    )
    assert shell.get("StreamUrl"), (
        f"admin shell response missing StreamUrl once session reached "
        f"{ready['Status']}: {shell!r}"
    )
    assert shell.get("TokenValue"), (
        f"admin shell response missing TokenValue once session reached "
        f"{ready['Status']}: {shell!r}"
    )
    if not_ready_seen:
        prefixes = {_without_internal_id(m) for m in not_ready_seen}
        assert len(prefixes) == 1, (
            f"StreamSessionAccessNotReadyException message varied across retries: {prefixes!r}"
        )

    # TERMINATED is outside the eligible set (ACTIVE, CONNECTED, PENDING_CLIENT_RECONNECTION,
    # RECONNECTING) and is final, so the rejection holds however fast the target is: real AWS
    # answers ValidationException naming that set, not StreamSessionAccessNotReadyException.
    _terminate_and_wait(gls, group["Arn"], session_arn)
    code, message = _error_code(
        lambda: gls.create_stream_session_admin_shell(
            Identifier=group["Arn"], StreamSessionIdentifier=session_arn
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException on a TERMINATED session, got {code!r}: {message!r}"
    )
    expected_message = (
        f"Stream session '{session_arn}' is not in ACTIVE, CONNECTED, "
        "PENDING_CLIENT_RECONNECTION or RECONNECTING status for session access"
    )
    assert _without_internal_id(message) == expected_message, (
        f"expected {expected_message!r}, got {message!r}"
    )


async def _start_via_webrtc(gls, group_arn, app_id):
    from aiortc import RTCPeerConnection

    pc = RTCPeerConnection()
    try:
        pc.createDataChannel("gameliftstreams-probe")
        # The streamed content is video+audio; an offer with only a data channel has no
        # media line for the service's WebRTC gateway to negotiate and is an
        # invalidSignalRequest, not a valid (if minimal) client.
        pc.addTransceiver("video", direction="recvonly")
        pc.addTransceiver("audio", direction="recvonly")
        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        # Send the offer only once ICE gathering completes -- an SDP with no candidates yet
        # is an invalidSignalRequest to the real service, not a signaling-protocol success.
        deadline = time.monotonic() + 15.0
        while pc.iceGatheringState != "complete" and time.monotonic() < deadline:
            await asyncio.sleep(0.2)
        signal_request = json.dumps(
            {"type": pc.localDescription.type, "sdp": pc.localDescription.sdp}
        )
        session = gls.start_stream_session(
            Identifier=group_arn,
            ApplicationIdentifier=app_id,
            Protocol="WebRTC",
            SignalRequest=signal_request,
        )
        return session["Arn"]
    finally:
        await pc.close()


def _error_code(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected rejection, but create_stream_session_admin_shell SUCCEEDED and returned {result!r}"
    )


def _without_internal_id(message):
    """GameLift Streams ends every error message with a per-request "(Internal ID: <uuid>)"."""
    stable, sep, rest = message.rpartition(" (Internal ID: ")
    assert sep and rest.endswith(")"), f"expected a trailing '(Internal ID: ...)', got {message!r}"
    return stable


def _create_admin_shell_until_ready(gls, group_arn, session_arn, timeout_s=60.0, interval_s=2.0):
    """Retry CreateStreamSessionAdminShell through any transient StreamSessionAccessNotReadyException
    once the session is eligible; returns (response, [not-ready messages seen])."""
    from botocore.exceptions import ClientError

    not_ready_seen = []
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return gls.create_stream_session_admin_shell(
                Identifier=group_arn, StreamSessionIdentifier=session_arn
            ), not_ready_seen
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "StreamSessionAccessNotReadyException":
                raise
            not_ready_seen.append(exc.response["Error"].get("Message", ""))
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateStreamSessionAdminShell still StreamSessionAccessNotReadyException "
                    f"after {timeout_s}s on an eligible session"
                )
            time.sleep(interval_s)


def _terminate_and_wait(gls, group_arn, session_arn, timeout_s=120.0, interval_s=5.0):
    """Terminate the session and wait for it to actually leave the application's "running
    sessions" set, so a later DeleteApplication/DeleteStreamGroup in the same teardown does
    not race a session the service still considers live. A session already TERMINATED
    or gone needs nothing."""
    from botocore.exceptions import ClientError

    try:
        current = gls.get_stream_session(Identifier=group_arn, StreamSessionIdentifier=session_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if current["Status"] == "TERMINATED":
        return
    try:
        gls.terminate_stream_session(Identifier=group_arn, StreamSessionIdentifier=session_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            session = gls.get_stream_session(Identifier=group_arn, StreamSessionIdentifier=session_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if session["Status"] == "TERMINATED":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stream session did not reach TERMINATED within {timeout_s}s during "
                f"teardown; last status={session['Status']!r}"
            )
        time.sleep(interval_s)


def _safe(fn, *not_found: str):
    """Run a cleanup call, swallowing only its own not-found codes; anything else re-raises
    so a failed delete is never recorded as clean."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] in not_found:
            return
        raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _wait_session_admin_shell_eligible(gls, group_arn, session_arn, timeout_s=180.0, interval_s=10.0):
    # Per the model, CreateStreamSessionAdminShell requires the session in one of these
    # statuses; TERMINATED/ERROR are terminal failures and must not be admitted into the
    # success set.
    eligible = {"ACTIVE", "CONNECTED", "PENDING_CLIENT_RECONNECTION", "RECONNECTING"}
    failed = {"TERMINATED", "ERROR"}
    deadline = time.monotonic() + timeout_s
    while True:
        session = gls.get_stream_session(Identifier=group_arn, StreamSessionIdentifier=session_arn)
        status = session["Status"]
        if status in eligible:
            return session
        if status in failed:
            raise AssertionError(
                f"stream session reached terminal status {status} before becoming "
                f"admin-shell-eligible: {session.get('StatusReason')}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stream session did not become admin-shell-eligible within {timeout_s}s; "
                f"last status={status!r}"
            )
        time.sleep(interval_s)


def _create_bucket(ctx, s3, suffix="app"):
    from botocore.exceptions import ClientError


    bucket = ctx.unique_name(f"sim2real-behav-gls-{suffix}-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is S3's CreateBucket special case: an explicit LocationConstraint there is rejected.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision real application content"
        )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(lambda: _safe(_cleanup, "NoSuchBucket"))
    return bucket


def _create_ready_application(ctx, gls, s3, script_body=b"#!/bin/sh\nexit 0\n", timeout_s=600.0):
    bucket = _create_bucket(ctx, s3, suffix="app")
    s3.put_object(Bucket=bucket, Key="app/run.sh", Body=script_body)
    app = gls.create_application(
        Description=ctx.unique_name("sim2real-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="run.sh",
        ApplicationSourceUri=f"s3://{bucket}/app/",
        Tags={"sim2real-env": "audit"},
    )
    app_id = app["Id"]
    ctx.on_cleanup(
        lambda: _safe(lambda: gls.delete_application(Identifier=app_id), "ResourceNotFoundException")
    )
    final = _poll_until(
        lambda: gls.get_application(Identifier=app_id),
        lambda a: a["Status"] in ("READY", "ERROR"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    if final["Status"] != "READY":
        raise AssertionError(f"application did not reach READY: {final.get('StatusReason')}")
    return final


def _create_active_stream_group(ctx, gls, location_configurations=None, timeout_s=300.0):
    kwargs = {
        "Description": ctx.unique_name("sim2real-gls-sg-"),
        "StreamClass": "gen6n_small",
        "Tags": {"sim2real-env": "audit"},
    }
    if location_configurations:
        kwargs["LocationConfigurations"] = location_configurations
    group = gls.create_stream_group(**kwargs)
    arn = group["Arn"]
    ctx.on_cleanup(
        lambda: _safe(lambda: gls.delete_stream_group(Identifier=arn), "ResourceNotFoundException")
    )
    final = _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        lambda g: g["Status"] in ("ACTIVE", "ACTIVE_WITH_ERRORS", "ERROR"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    if final["Status"] != "ACTIVE":
        raise AssertionError(
            f"stream group did not reach ACTIVE: {final['Status']}/{final.get('StatusReason')}"
        )
    return final


def _wait_location_active(ctx, gls, arn, timeout_s=600.0):
    def _location_is_active(group):
        for loc in group["LocationStates"]:
            if loc["LocationName"] == ctx.region:
                return loc["Status"] == "ACTIVE"
        return False

    return _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        _location_is_active,
        timeout_s=timeout_s,
        interval_s=15.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
