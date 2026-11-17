"""rtmp-publish-full-participant-lifecycle."""
from __future__ import annotations

import shutil
import subprocess
import time
from typing import Any, Callable

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "rtmp-publish-full-participant-lifecycle"
GROUP = "native-protocol"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real RTMPS publisher (ffmpeg) makes an IngestConfiguration go ACTIVE, creates a
    live StageSession/Participant, and the session/participant/ingest cleanly unwind once the
    publisher stops; deleting the ACTIVE ingest configuration without force is refused meanwhile.
    """
    # A ~40s live RTMPS publish runs on every target; ffmpeg is the native RTMPS client.
    require_tools("ffmpeg")
    ffmpeg = shutil.which("ffmpeg")

    client = ctx.client("ivs-realtime")

    stage = client.create_stage(
        name=ctx.unique_name("sim2real-rtstage"), tags={"purpose": "sim2real"}
    )["stage"]
    stage_arn = stage["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_stage(arn=stage_arn)))

    ingest = client.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ingest"),
        stageArn=stage_arn,
        ingestProtocol="RTMPS",
        tags={"purpose": "sim2real"},
    )["ingestConfiguration"]
    ingest_arn = ingest["arn"]
    stream_key = ingest["streamKey"]
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_ingest_configuration(arn=ingest_arn, force=True)))
    assert ingest["state"] == "INACTIVE", f"expected a freshly created ingest configuration to start INACTIVE, got {ingest['state']!r}"

    endpoint = client.get_stage(arn=stage_arn)["stage"]["endpoints"]["rtmps"]
    assert endpoint, "expected get_stage to report a non-empty rtmps ingest endpoint"
    # GetStage reports the RTMPS endpoint as a full base URL (scheme, port and app path).
    publish_url = f"{ctx.endpoint_url(endpoint)}{stream_key}"

    cmd = [
        ffmpeg, "-loglevel", "error", "-re",
        "-f", "lavfi", "-i", "testsrc=d=40:s=1280x720:r=30,format=yuv420p",
        "-f", "lavfi", "-i", "sine=f=440:b=4:d=40",
        "-c:v", "libx264", "-b:v", "1500k", "-g", "60", "-bf", "0",
        "-profile:v", "baseline", "-preset", "veryfast", "-tune", "zerolatency",
        "-x264opts", "sliced-threads=0",
        "-c:a", "aac", "-ac", "2", "-b:a", "128k", "-ar", "48000",
        "-f", "flv", publish_url,
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    ctx.on_cleanup(lambda: _safe(lambda: proc.kill() if proc.poll() is None else None))

    try:
        active_ingest = _poll_until(
            lambda: client.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"],
            lambda ic: ic["state"] == "ACTIVE",
            timeout_s=60,
        )
    except AssertionError:
        stderr = proc.stderr.read().decode("utf-8", "replace")[-2000:] if proc.stderr else ""
        raise AssertionError(f"ingest configuration never reached ACTIVE; ffmpeg stderr tail: {stderr}")
    participant_id = active_ingest["participantId"]

    stage_now = _poll_until(
        lambda: client.get_stage(arn=stage_arn)["stage"],
        lambda s: bool(s.get("activeSessionId")),
        timeout_s=30,
    )
    session_id = stage_now["activeSessionId"]

    participant = _poll_until(
        lambda: client.get_participant(
            stageArn=stage_arn, sessionId=session_id, participantId=participant_id
        )["participant"],
        lambda p: p["state"] == "CONNECTED" and p.get("published"),
        timeout_s=30,
    )
    assert participant["protocol"] == "RTMPS", f"expected the connected participant's protocol to be RTMPS, got {participant['protocol']!r}"

    # Negative, in-flow: deleting an ACTIVE ingest configuration without force is
    # rejected, and the resource is provably still there (get still succeeds).
    conflict_code, conflict_message = _error(lambda: client.delete_ingest_configuration(arn=ingest_arn))
    assert conflict_code == "ConflictException", f"expected deleting an ACTIVE ingest configuration without force to raise ConflictException, got {conflict_code!r}"
    expected_conflict = (
        f"Unable to mutate resource {ingest_arn} while participant is actively publishing"
    )
    assert conflict_message == expected_conflict, f"expected {expected_conflict!r}, got {conflict_message!r}"
    active_state = client.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"]["state"]
    assert active_state == "ACTIVE", f"expected the rejected delete to leave the ingest configuration ACTIVE, got {active_state!r}"

    # Let the publisher finish naturally (bounded: the test clip is 40s).
    proc.wait(timeout=90)

    inactive_ingest = _poll_until(
        lambda: client.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"],
        lambda ic: ic["state"] == "INACTIVE",
        timeout_s=60,
    )
    assert inactive_ingest["state"] == "INACTIVE", f"expected the ingest configuration to return to INACTIVE after the publisher stopped, got {inactive_ingest['state']!r}"

    disconnected = _poll_until(
        lambda: client.get_participant(
            stageArn=stage_arn, sessionId=session_id, participantId=participant_id
        )["participant"],
        lambda p: p["state"] == "DISCONNECTED",
        timeout_s=60,
    )
    assert disconnected["state"] == "DISCONNECTED", f"expected the participant to transition to DISCONNECTED, got {disconnected['state']!r}"

    events = client.list_participant_events(
        stageArn=stage_arn, sessionId=session_id, participantId=participant_id
    )["events"]
    event_names = {e["name"] for e in events}
    assert "JOINED" in event_names, f"expected a JOINED event for the participant, got {sorted(event_names)}"
    assert "LEFT" in event_names, f"expected a LEFT event for the participant, got {sorted(event_names)}"

    ended_session = _poll_until(
        lambda: client.get_stage_session(stageArn=stage_arn, sessionId=session_id)["stageSession"],
        lambda s: s.get("endTime") is not None,
        timeout_s=240,
    )
    assert ended_session["endTime"] is not None, "expected the stage session to record an endTime once the sole participant left"

    # Positive control: now that the ingest is INACTIVE, delete without force succeeds.
    client.delete_ingest_configuration(arn=ingest_arn)
    deleted_code, deleted_message = _error(lambda: client.get_ingest_configuration(arn=ingest_arn))
    assert deleted_code == "ResourceNotFoundException", f"expected get_ingest_configuration on a deleted ingest to raise ResourceNotFoundException, got {deleted_code!r}"
    assert deleted_message == f"Resource: {ingest_arn} not found", deleted_message


# ===== helpers =====
def _safe(fn: Callable[[], Any]) -> None:
    """Run a teardown step; a resource already gone is clean, any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts what AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
