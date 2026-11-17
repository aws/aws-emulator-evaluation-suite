"""rtmp-publish-lifecycle-and-disconnect."""
from __future__ import annotations

import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "rtmp-publish-lifecycle-and-disconnect"
GROUP = "native-protocol"
SERVICES = ["ivs-realtime"]


def _poll_until(probe, predicate, timeout_s=45.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _ffmpeg_publish(url: str, duration_s: int):
    """Start an ffmpeg process publishing a synthetic test signal to `url` via RTMP."""
    cmd = [
        "ffmpeg", "-loglevel", "error", "-re",
        "-f", "lavfi", "-i", f"testsrc=size=640x360:rate=30",
        "-f", "lavfi", "-i", "sine=frequency=1000",
        "-pix_fmt", "yuv420p", "-profile:v", "baseline", "-level", "3.0",
        "-r", "30", "-g", "60",
        "-c:v", "libx264", "-b:v", "800k", "-c:a", "aac",
        "-t", str(duration_s), "-f", "flv", url,
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An RTMP publish to a stage's ingest endpoint turns the IngestConfiguration ACTIVE, the stage
    session live and the participant CONNECTED and published; DisconnectParticipant then yields
    DISCONNECTED, JOINED and LEFT events, and INACTIVE ingest, each read polled to its value.
    """
    require_tools("ffmpeg")

    ivs = ctx.client("ivs-realtime")
    stage = ivs.create_stage(
        name=ctx.unique_name("sim2real-stage-"), tags={"sim2real": CHECK}
    )["stage"]
    stage_arn = stage["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))

    ingest = ivs.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ingest-"),
        stageArn=stage_arn,
        ingestProtocol="RTMP",
        insecureIngest=True,
        tags={"sim2real": CHECK},
    )["ingestConfiguration"]
    ingest_arn = ingest["arn"]
    ctx.on_cleanup(lambda: ivs.delete_ingest_configuration(arn=ingest_arn, force=True))

    endpoint = ctx.endpoint_url(stage["endpoints"]["rtmp"]).rstrip("/")
    stream_key = ingest["streamKey"]
    # AWS's own private-ingest documentation constructs the publish URL as
    # "<endpoint>/app/<stream_key>"; try that first and fall back to a direct
    # "<endpoint>/<stream_key>" in case this account's endpoint already embeds the app path.
    candidate_urls = [f"{endpoint}/app/{stream_key}", f"{endpoint}/{stream_key}"]

    proc = None
    active_ingest = None
    try:
        for url in candidate_urls:
            proc = _ffmpeg_publish(url, duration_s=60)
            active_ingest = _poll_until(
                lambda: ivs.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"],
                lambda c: c["state"] == "ACTIVE",
                timeout_s=20.0,
            )
            if active_ingest and active_ingest["state"] == "ACTIVE":
                break
            proc.kill()
            proc.wait(timeout=10)
            proc = None

        assert active_ingest is not None and active_ingest["state"] == "ACTIVE", active_ingest
        participant_id = active_ingest["participantId"]
        assert participant_id, active_ingest

        # No documented ordering ties ingest ACTIVE to the stage session and participant state:
        # poll each read to its live value.
        stage_now = _poll_until(
            lambda: ivs.get_stage(arn=stage_arn)["stage"],
            lambda st: bool(st.get("activeSessionId")),
            timeout_s=30.0,
        )
        session_id = stage_now.get("activeSessionId")
        assert session_id, stage_now

        participant = _poll_until(
            lambda: ivs.get_participant(
                stageArn=stage_arn, sessionId=session_id, participantId=participant_id
            )["participant"],
            lambda p: p["state"] == "CONNECTED" and p["published"] is True,
            timeout_s=30.0,
        )
        assert participant["state"] == "CONNECTED", participant["state"]
        assert participant["published"] is True, participant

        # Forcibly disconnect the live RTMP publisher via the control plane.
        ivs.disconnect_participant(
            stageArn=stage_arn, participantId=participant_id, reason="sim2real-behavioral-check"
        )

        disconnected = _poll_until(
            lambda: ivs.get_participant(
                stageArn=stage_arn, sessionId=session_id, participantId=participant_id
            )["participant"],
            lambda p: p["state"] == "DISCONNECTED",
            timeout_s=30.0,
        )
        assert disconnected["state"] == "DISCONNECTED", disconnected["state"]

        events = _poll_until(
            lambda: ivs.list_participant_events(
                stageArn=stage_arn, sessionId=session_id, participantId=participant_id
            )["events"],
            lambda evs: {"JOINED", "LEFT"} <= {e["name"] for e in evs},
            timeout_s=30.0,
        )
        event_names = [e["name"] for e in events]
        assert "JOINED" in event_names, event_names
        assert "LEFT" in event_names, event_names

        inactive_ingest = _poll_until(
            lambda: ivs.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"],
            lambda c: c["state"] == "INACTIVE",
            timeout_s=30.0,
        )
        assert inactive_ingest["state"] == "INACTIVE", inactive_ingest["state"]
    finally:
        if proc is not None:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except Exception:
                pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
