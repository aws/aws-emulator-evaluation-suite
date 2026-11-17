"""stage-active-session-absent-until-participant."""
from __future__ import annotations

import subprocess
import time
from typing import Any, Callable

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "stage-active-session-absent-until-participant"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags(
    "axis:happy-path", "cap:c1", "cap:c4", "cap:c6",
    "concern:representation", "concern:data-plane",
    "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A fresh Stage has no activeSessionId and an empty ListStageSessions; once an RTMP publisher
    connects, GetStage reports an activeSessionId and ListStageSessions lists it (both polled).
    """
    require_tools("ffmpeg")

    ivs = ctx.client("ivs-realtime")
    created = ivs.create_stage(name=ctx.unique_name("sim2real-stage-"))
    arn = created["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=arn))

    # The CreateStage response itself must not carry an active session yet.
    assert not created["stage"].get("activeSessionId"), created["stage"]

    # Nor does a fresh GetStage report one -- no StageSession has begun.
    fetched = ivs.get_stage(arn=arn)["stage"]
    assert fetched["arn"] == arn, fetched
    assert not fetched.get("activeSessionId"), fetched

    # ListStageSessions for this stage must be empty (no session has ever started).
    sessions = ivs.list_stage_sessions(stageArn=arn)["stageSessions"]
    assert sessions == [], sessions

    # Positive control: a real RTMP publisher joining the stage must flip both facts.
    # Without this leg, an emulator that never models sessions at all -- always
    # reporting absence -- would pass every assertion above.
    ingest = ivs.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ingest-"),
        stageArn=arn,
        ingestProtocol="RTMP",
        insecureIngest=True,
    )["ingestConfiguration"]
    ingest_arn = ingest["arn"]
    ctx.on_cleanup(lambda: ivs.delete_ingest_configuration(arn=ingest_arn, force=True))

    endpoint = ctx.endpoint_url(fetched["endpoints"]["rtmp"]).rstrip("/")
    stream_key = ingest["streamKey"]
    # AWS's own private-ingest documentation constructs the publish URL as
    # "<endpoint>/app/<stream_key>"; try that first and fall back to a direct
    # "<endpoint>/<stream_key>" in case this account's endpoint already embeds the app path.
    candidate_urls = [f"{endpoint}/app/{stream_key}", f"{endpoint}/{stream_key}"]

    proc = None
    active_ingest = None
    try:
        for url in candidate_urls:
            proc = _ffmpeg_publish(url, duration_s=45)
            active_ingest = _poll_until(
                lambda: ivs.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"],
                lambda c: c["state"] == "ACTIVE",
                timeout_s=20.0,
            )
            if active_ingest["state"] == "ACTIVE":
                break
            proc.kill()
            proc.wait(timeout=10)
            proc = None

        assert active_ingest["state"] == "ACTIVE", active_ingest
        participant_id = active_ingest["participantId"]
        assert participant_id, active_ingest

        # No documented ordering ties ingest ACTIVE to the stage session: poll both reads.
        live = _poll_until(
            lambda: ivs.get_stage(arn=arn)["stage"],
            lambda st: bool(st.get("activeSessionId")),
            timeout_s=30.0,
        )
        session_id = live.get("activeSessionId")
        assert session_id, live

        live_sessions = _poll_until(
            lambda: ivs.list_stage_sessions(stageArn=arn)["stageSessions"],
            lambda listed: session_id in [s["sessionId"] for s in listed],
            timeout_s=30.0,
        )
        live_session_ids = [s["sessionId"] for s in live_sessions]
        assert session_id in live_session_ids, (session_id, live_session_ids)

        # Wind the publish down deterministically (rather than waiting on the ffmpeg
        # process to die) so cleanup does not race an AWS-side session teardown.
        ivs.disconnect_participant(
            stageArn=arn, participantId=participant_id, reason="sim2real-audit-cleanup"
        )
        inactive_ingest = _poll_until(
            lambda: ivs.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"],
            lambda c: c["state"] == "INACTIVE",
            timeout_s=30.0,
        )
        assert inactive_ingest["state"] == "INACTIVE", inactive_ingest
    finally:
        if proc is not None:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except Exception:
                pass


def _ffmpeg_publish(url: str, duration_s: int):
    """Start an ffmpeg process publishing a synthetic test signal to `url` via RTMP."""
    cmd = [
        "ffmpeg", "-loglevel", "error", "-re",
        "-f", "lavfi", "-i", "testsrc=size=640x360:rate=30",
        "-f", "lavfi", "-i", "sine=frequency=1000",
        "-pix_fmt", "yuv420p", "-profile:v", "baseline", "-level", "3.0",
        "-r", "30", "-g", "60",
        "-c:v", "libx264", "-b:v", "800k", "-c:a", "aac",
        "-t", str(duration_s), "-f", "flv", url,
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
