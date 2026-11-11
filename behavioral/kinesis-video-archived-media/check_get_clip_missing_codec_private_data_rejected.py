"""get-clip-missing-codec-private-data-rejected."""
from __future__ import annotations

import http.client
import json
import socket
import time
import urllib.parse

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-clip-missing-codec-private-data-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-archived-media"]

_SOCKET_TIMEOUT_S = 25.0
_ACK_BUDGET_S = 60.0

# A real H.264 baseline SPS/PPS/IDR triple (64x64), encoded once with x264.
_SPS = bytes.fromhex("6742c00adc426c044000000300400000030103c489e0")
_PPS = bytes.fromhex("68ce0f2c80")
_FRAME = bytes.fromhex("65888404bc4628000cc4c700017d68e00022432727275d75d75d75d75d75d780")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetClip rejects a stream whose track declares no CodecPrivate with
    MissingCodecPrivateDataException, while the same ingest-and-clip workflow succeeds for a
    sibling stream whose track declares the AVCDecoderConfigurationRecord.

    Reference: https://docs.aws.amazon.com/kinesisvideostreams/latest/APIReference/API_reader_GetClip.html
    """
    kv = ctx.client("kinesisvideo")

    control_stream = _create_active_stream(ctx, kv, "sim2real-kvam-ctrl-")
    control_start = time.time()
    _ingest_one_frame(ctx, kv, control_stream, control_start, with_codec_private=True)
    control_clip = _get_clip(ctx, kv, control_stream, control_start)
    assert control_clip["ContentType"] == "video/mp4", (
        f"positive control: expected 'video/mp4', got {control_clip['ContentType']!r}"
    )
    payload = control_clip["Payload"]
    try:
        control_body = payload.read()
    finally:
        payload.close()
    assert control_body[4:8] == b"ftyp", (
        f"positive control must clip the stream whose track declares CodecPrivate, "
        f"got {control_body[:12]!r}"
    )

    broken_stream = _create_active_stream(ctx, kv, "sim2real-kvam-nocp-")
    broken_start = time.time()
    _ingest_one_frame(ctx, kv, broken_stream, broken_start, with_codec_private=False)

    err = _error(lambda: _get_clip(ctx, kv, broken_stream, broken_start))
    expected = ("MissingCodecPrivateDataException", "Missing codec private data in fragment for track 1.")
    assert err == expected, (
        f"expected {expected!r} for a track with no CodecPrivate, got {err!r}"
    )


def _ingest_one_frame(ctx, kv, stream, producer_start, *, with_codec_private):
    status, _headers, acks, tail = _put_media(
        ctx, kv, _data_endpoint(kv, stream["name"], "PUT_MEDIA"), stream["name"],
        _mkv([_FRAME], [0], with_codec_private=with_codec_private), producer_start,
        expect_persisted=1,
    )
    assert status == 200, f"PutMedia expected HTTP 200, got {status!r} (tail {tail[:200]!r})"
    persisted = _persisted(acks)
    assert len(persisted) == 1, f"expected one PERSISTED fragment, got {persisted!r}"
    list_media = ctx.client(
        "kinesis-video-archived-media",
        endpoint_url=ctx.endpoint_url(_data_endpoint(kv, stream["name"], "LIST_FRAGMENTS")),
    )
    fragments = _await_fragments(list_media, stream["name"], producer_start - 60, producer_start + 600, 1)
    assert len(fragments) == 1, f"expected one listed fragment, got {fragments!r}"


def _get_clip(ctx, kv, stream, producer_start):
    clip_media = ctx.client(
        "kinesis-video-archived-media",
        endpoint_url=ctx.endpoint_url(_data_endpoint(kv, stream["name"], "GET_CLIP")),
    )
    return clip_media.get_clip(
        StreamName=stream["name"],
        ClipFragmentSelector={
            "FragmentSelectorType": "PRODUCER_TIMESTAMP",
            "TimestampRange": {"StartTimestamp": producer_start - 60, "EndTimestamp": producer_start + 600},
        },
    )


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError("expected GetClip to be refused, but it succeeded")


# --- Matroska writer -----------------------------------------------------------------

def _vint(n):
    for width in range(1, 9):
        if n < (1 << (7 * width)) - 1:
            return (n | (1 << (7 * width))).to_bytes(width, "big")
    raise AssertionError(f"{n!r} does not fit an EBML vint")


def _uint(n):
    return b"\x00" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")


def _el(element_id, payload):
    return element_id + _vint(len(payload)) + payload


def _avcc(sps, pps):
    out = bytes([1, sps[1], sps[2], sps[3], 0xFF])
    out += bytes([0xE1]) + len(sps).to_bytes(2, "big") + sps
    out += bytes([1]) + len(pps).to_bytes(2, "big") + pps
    return out


def _mkv(frames, timecodes_ms, *, block_track=1, with_codec_private=True):
    assert len(frames) == len(timecodes_ms), "one timecode per frame"
    header = _el(b"\x1a\x45\xdf\xa3", b"".join([
        _el(b"\x42\x86", _uint(1)),
        _el(b"\x42\xf7", _uint(1)),
        _el(b"\x42\xf2", _uint(4)),
        _el(b"\x42\xf3", _uint(8)),
        _el(b"\x42\x82", b"matroska"),
        _el(b"\x42\x87", _uint(2)),
        _el(b"\x42\x85", _uint(2)),
    ]))
    info = _el(b"\x15\x49\xa9\x66", b"".join([
        _el(b"\x2a\xd7\xb1", _uint(1000000)),
        _el(b"\x4d\x80", b"sim2real"),
        _el(b"\x57\x41", b"sim2real"),
    ]))
    track_parts = [
        _el(b"\xd7", _uint(block_track)),
        _el(b"\x73\xc5", _uint(block_track)),
        _el(b"\x83", _uint(1)),
        _el(b"\x9c", _uint(0)),
        _el(b"\x86", b"V_MPEG4/ISO/AVC"),
    ]
    if with_codec_private:
        track_parts.append(_el(b"\x63\xa2", _avcc(_SPS, _PPS)))
    track_parts.append(_el(b"\xe0", _el(b"\xb0", _uint(64)) + _el(b"\xba", _uint(64))))
    entries = _el(b"\xae", b"".join(track_parts))
    out = (
        header + b"\x18\x53\x80\x67" + b"\x01\xff\xff\xff\xff\xff\xff\xff"
        + info + _el(b"\x16\x54\xae\x6b", entries)
    )
    for frame, timecode in zip(frames, timecodes_ms):
        sample = len(frame).to_bytes(4, "big") + frame
        block = (
            _vint(block_track)
            + (0).to_bytes(2, "big", signed=True)
            + b"\x80"
            + sample
        )
        out += _el(b"\x1f\x43\xb6\x75", _el(b"\xe7", _uint(timecode)) + _el(b"\xa3", block))
    return out


# --- PutMedia ------------------------------------------------------------------------

def _put_media(ctx, kv, endpoint, stream_name, body, producer_start, *,
               timecode_type="RELATIVE", content_sha256="UNSIGNED-PAYLOAD",
               expect_persisted=0, path="/putMedia"):
    """PutMedia, hand-signed over raw HTTP: it is absent from every AWS SDK (the kinesisvideo
    model's 32 operations and kinesis-video-media's single GetMedia do not include it), so no
    botocore client can send it.
    """
    parsed = urllib.parse.urlparse(ctx.endpoint_url(endpoint))
    host = parsed.netloc
    headers = {
        "x-amzn-stream-name": stream_name,
        "x-amzn-fragment-timecode-type": timecode_type,
        "x-amzn-producer-start-timestamp": f"{producer_start:.3f}",
        "Content-Type": "application/octet-stream",
        "x-amz-content-sha256": content_sha256,
    }
    request = AWSRequest(
        method="POST", url=f"{parsed.scheme}://{host}{path}", data=body, headers=headers
    )
    frozen = _frozen_credentials(kv)

    class _Auth(SigV4Auth):
        def payload(self, request):  # noqa: ARG002 - the header value IS the signed payload
            return content_sha256

    _Auth(frozen, "kinesisvideo", ctx.region).add_auth(request)
    opener = http.client.HTTPConnection if parsed.scheme == "http" else http.client.HTTPSConnection
    conn = opener(host, timeout=_SOCKET_TIMEOUT_S)
    acks, buf = [], b""
    try:
        conn.request("POST", path, body=body, headers=dict(request.headers.items()))
        response = conn.getresponse()
        status = response.status
        response_headers = {k.lower(): v for k, v in response.getheaders()}
        decoder = json.JSONDecoder()
        deadline = time.monotonic() + _ACK_BUDGET_S
        while time.monotonic() < deadline:
            try:
                chunk = response.read(2048)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            buf += chunk
            while True:
                stripped = buf.lstrip()
                if not stripped:
                    buf = b""
                    break
                try:
                    obj, end = decoder.raw_decode(stripped.decode("utf-8", "replace"))
                except ValueError:
                    buf = stripped
                    break
                acks.append(obj)
                buf = stripped[end:]
            if _ack_error(acks)[0] is not None:
                break
            if expect_persisted and len(_persisted(acks)) >= expect_persisted:
                break
        return status, response_headers, acks, buf
    finally:
        conn.close()


def _frozen_credentials(client):
    raw = client._request_signer._credentials
    return raw.get_frozen_credentials() if hasattr(raw, "get_frozen_credentials") else raw


def _persisted(acks):
    return [a["FragmentNumber"] for a in acks if a.get("EventType") == "PERSISTED"]


def _ack_error(acks):
    for ack in acks:
        if ack.get("EventType") == "ERROR":
            return ack.get("ErrorCode"), ack.get("ErrorId")
    return None, None


# --- control plane and archived-media reads ------------------------------------------

def _wait_stream_active(kv, name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_stream(StreamName=name)["StreamInfo"]["Status"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} never reached ACTIVE (last status={status})")


def _create_active_stream(ctx, kv, prefix, *, retention_hours=1):
    name = ctx.unique_name(prefix)
    arn = kv.create_stream(
        StreamName=name, DataRetentionInHours=retention_hours, MediaType="video/h264",
        Tags={"sim2real": CHECK},
    )["StreamARN"]
    ctx.on_cleanup(lambda: kv.delete_stream(StreamARN=arn))
    _wait_stream_active(kv, name)
    return {"name": name, "arn": arn}


def _data_endpoint(kv, stream_name, api_name):
    endpoint = kv.get_data_endpoint(StreamName=stream_name, APIName=api_name)["DataEndpoint"]
    assert endpoint and "://" in endpoint, (
        f"GetDataEndpoint({api_name}) returned {endpoint!r}, not a URL"
    )
    return endpoint


def _list_fragments(client, stream_name, start_ts, end_ts):
    selector = {
        "FragmentSelectorType": "PRODUCER_TIMESTAMP",
        "TimestampRange": {"StartTimestamp": start_ts, "EndTimestamp": end_ts},
    }
    fragments, token = [], None
    while True:
        kwargs = {"StreamName": stream_name, "FragmentSelector": selector}
        if token:
            kwargs["NextToken"] = token
        page = client.list_fragments(**kwargs)
        fragments.extend(page.get("Fragments", []))
        token = page.get("NextToken")
        if not token:
            return fragments


def _await_fragments(client, stream_name, start_ts, end_ts, expect_count, *, budget_s=45.0):
    deadline = time.monotonic() + budget_s
    while True:
        fragments = _list_fragments(client, stream_name, start_ts, end_ts)
        if len(fragments) >= expect_count or time.monotonic() >= deadline:
            return fragments
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
