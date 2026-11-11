"""viewer-slot-limit-enforced-concurrent."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "viewer-slot-limit-enforced-concurrent"
GROUP = "concurrency"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of 5 concurrent JoinStorageSessionAsViewer calls with distinct client ids, 1 to 3 succeed (the 3-viewer cap
    holds under contention), and every failure is ClientLimitExceededException with the viewer-cap message or
    the session-creation retry message."""
    setup = _create_channel_and_stream(ctx)
    kv = setup["kv"]
    channel_arn = setup["channel_arn"]
    webrtc = ctx.client(
        "kinesis-video-webrtc-storage", endpoint_url=_webrtc_endpoint(kv, channel_arn, "VIEWER")
    )
    client_ids = [ctx.unique_name(f"viewer-{i}-") for i in range(5)]

    def _join(client_id):
        return _client_error(
            lambda: webrtc.join_storage_session_as_viewer(channelArn=channel_arn, clientId=client_id)
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        codes = list(pool.map(_join, client_ids))

    successes = [c for c in codes if c is None]
    failures = [c for c in codes if c is not None]
    assert 1 <= len(successes) <= 3, (
        f"expected between 1 and 3 (inclusive) of 5 concurrent viewer joins to succeed, got {codes}"
    )
    # The 3-viewer cap and the per-session creation throttle answer with the same code and distinct messages.
    expected = {
        ("ClientLimitExceededException", "Maximum number of viewers connected to the session!"),
        ("ClientLimitExceededException", "Session in creation, please retry"),
    }
    assert all((c.get("Code"), c.get("Message")) in expected for c in failures), (
        f"unexpected failures: {failures}"
    )


def _wait_channel_active(kv, channel_arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_signaling_channel(ChannelARN=channel_arn)["ChannelInfo"]["ChannelStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"signaling channel never reached ACTIVE (last status={status})")


def _wait_stream_active(kv, stream_arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_stream(StreamARN=stream_arn)["StreamInfo"]["Status"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream never reached ACTIVE (last status={status})")


def _safe_delete_channel(kv, channel_arn):
    try:
        kv.delete_signaling_channel(ChannelARN=channel_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_stream(kv, stream_arn):
    try:
        kv.delete_stream(StreamARN=stream_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_unlink(kv, channel_arn):
    try:
        kv.update_media_storage_configuration(
            ChannelARN=channel_arn, MediaStorageConfiguration={"Status": "DISABLED"}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _webrtc_endpoint(kv, channel_arn, role):
    resp = kv.get_signaling_channel_endpoint(
        ChannelARN=channel_arn,
        SingleMasterChannelEndpointConfiguration={"Protocols": ["WEBRTC"], "Role": role},
    )
    for e in resp["ResourceEndpointList"]:
        if e["Protocol"] == "WEBRTC":
            return e["ResourceEndpoint"]
    raise AssertionError(f"no WEBRTC endpoint returned for role={role}")


def _create_channel_and_stream(ctx, link_storage=True, retention_hours=1):
    kv = ctx.client("kinesisvideo")
    channel_name = ctx.unique_name("sim2real-kvsrtc-ch-")
    stream_name = ctx.unique_name("sim2real-kvsrtc-strm-")
    channel_arn = kv.create_signaling_channel(
        ChannelName=channel_name,
        ChannelType="SINGLE_MASTER",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ChannelARN"]
    ctx.on_cleanup(lambda: _safe_delete_channel(kv, channel_arn))
    stream_arn = kv.create_stream(
        StreamName=stream_name,
        DataRetentionInHours=retention_hours,
        Tags={"sim2real": CHECK},
    )["StreamARN"]
    ctx.on_cleanup(lambda: _safe_delete_stream(kv, stream_arn))
    _wait_channel_active(kv, channel_arn)
    _wait_stream_active(kv, stream_arn)
    if link_storage:
        kv.update_media_storage_configuration(
            ChannelARN=channel_arn,
            MediaStorageConfiguration={"StreamARN": stream_arn, "Status": "ENABLED"},
        )
        ctx.on_cleanup(lambda: _safe_unlink(kv, channel_arn))
    return {
        "kv": kv,
        "channel_arn": channel_arn,
        "stream_arn": stream_arn,
        "channel_name": channel_name,
        "stream_name": stream_name,
    }


def _client_error(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
