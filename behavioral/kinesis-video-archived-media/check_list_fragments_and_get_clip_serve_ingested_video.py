"""list-fragments-and-get-clip-serve-ingested-video."""
from __future__ import annotations

import http.client
import json
import socket
import time
import urllib.parse

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "list-fragments-and-get-clip-serve-ingested-video"
GROUP = "media-data-plane"
SERVICES = ["kinesis-video-archived-media"]

_SOCKET_TIMEOUT_S = 25.0
_ACK_BUDGET_S = 60.0

# A real two-frame H.264 baseline elementary stream (64x64, one IDR slice per frame), encoded once
# with x264: genuine decodable NAL units, so GetClip's MP4 mux carries real video rather than
# opaque bytes.
_SPS = bytes.fromhex("6742c00adc426c044000000300400000030103c489e0")
_PPS = bytes.fromhex("68ce0f2c80")
_FRAME_1 = bytes.fromhex("65888404bc4628000cc4c700017d68e00022432727275d75d75d75d75d75d780")
_FRAME_2 = bytes.fromhex("658882017fffffc11450001439f1c0006c1a380008d0c9c9c9d75d75d75d75d75d75e0")


@tags(
    "axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "concern:representation",
    "dp:endpoint", "plane:data",
)
def run(ctx) -> None:
    """Frames ingested through PutMedia come back as a ListFragments index reporting their exact
    sizes and as a GetClip MP4 whose video track carries the ingested frame bytes.

    Reference: https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_dataplane_PutMedia.html
    Reference: https://docs.aws.amazon.com/kinesisvideostreams/latest/APIReference/API_reader_GetClip.html
    """
    kv = ctx.client("kinesisvideo")
    stream = _create_active_stream(ctx, kv)

    start = time.time()
    status, _headers, acks, tail = _put_media(
        ctx, kv, _data_endpoint(kv, stream["name"], "PUT_MEDIA"), stream["name"],
        _mkv([_FRAME_1, _FRAME_2], [0, 1000]), start, expect_persisted=2,
    )
    assert status == 200, f"PutMedia expected HTTP 200, got {status!r} (tail {tail[:200]!r})"
    persisted = _persisted(acks)
    assert len(persisted) == 2, f"expected two PERSISTED fragments, got {persisted!r}"

    list_media = ctx.client(
        "kinesis-video-archived-media",
        endpoint_url=ctx.endpoint_url(_data_endpoint(kv, stream["name"], "LIST_FRAGMENTS")),
    )
    fragments = _await_fragments(list_media, stream["name"], start - 60, start + 600, 2)
    listed = {f["FragmentNumber"] for f in fragments}
    assert listed == set(persisted), (
        f"ListFragments must report exactly the PERSISTED fragments {sorted(persisted)!r}, "
        f"got {sorted(listed)!r}"
    )
    for fragment in fragments:
        assert fragment["FragmentSizeInBytes"] > len(_FRAME_1), (
            f"fragment {fragment['FragmentNumber']!r} reports "
            f"{fragment['FragmentSizeInBytes']!r} bytes, too small to hold the ingested frame"
        )
        assert fragment["ServerTimestamp"] is not None, (
            f"fragment {fragment['FragmentNumber']!r} has no ServerTimestamp: {fragment!r}"
        )

    clip_media = ctx.client(
        "kinesis-video-archived-media",
        endpoint_url=ctx.endpoint_url(_data_endpoint(kv, stream["name"], "GET_CLIP")),
    )
    clip = clip_media.get_clip(
        StreamName=stream["name"],
        ClipFragmentSelector={
            "FragmentSelectorType": "PRODUCER_TIMESTAMP",
            "TimestampRange": {"StartTimestamp": start - 60, "EndTimestamp": start + 600},
        },
    )
    assert clip["ContentType"] == "video/mp4", f"expected 'video/mp4', got {clip['ContentType']!r}"
    payload = clip["Payload"]
    try:
        body = payload.read()
    finally:
        payload.close()
    assert body[4:8] == b"ftyp", f"GetClip must return an MP4 container, got {body[:12]!r}"
    assert _FRAME_1[1:] in body and _FRAME_2[1:] in body, (
        "GetClip's MP4 must carry both ingested frames' payload bytes"
    )


# --- Matroska writer -----------------------------------------------------------------
# KVS ingests MKV and treats ONE Cluster as ONE fragment.

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
    """An AVCDecoderConfigurationRecord from a real SPS/PPS pair, as Matroska's CodecPrivate."""
    out = bytes([1, sps[1], sps[2], sps[3], 0xFF])
    out += bytes([0xE1]) + len(sps).to_bytes(2, "big") + sps
    out += bytes([1]) + len(pps).to_bytes(2, "big") + pps
    return out


def _mkv(frames, timecodes_ms, *, block_track=1):
    """A Matroska stream with one Cluster (= one KVS fragment) per frame."""
    assert len(frames) == len(timecodes_ms), "one timecode per frame"
    header = _el(b"\x1a\x45\xdf\xa3", b"".join([
        _el(b"\x42\x86", _uint(1)),            # EBMLVersion
        _el(b"\x42\xf7", _uint(1)),            # EBMLReadVersion
        _el(b"\x42\xf2", _uint(4)),            # EBMLMaxIDLength
        _el(b"\x42\xf3", _uint(8)),            # EBMLMaxSizeLength
        _el(b"\x42\x82", b"matroska"),        # DocType
        _el(b"\x42\x87", _uint(2)),            # DocTypeVersion
        _el(b"\x42\x85", _uint(2)),            # DocTypeReadVersion
    ]))
    info = _el(b"\x15\x49\xa9\x66", b"".join([
        _el(b"\x2a\xd7\xb1", _uint(1000000)),  # TimecodeScale: 1 ms
        _el(b"\x4d\x80", b"sim2real"),         # MuxingApp
        _el(b"\x57\x41", b"sim2real"),         # WritingApp
    ]))
    entries = _el(b"\xae", b"".join([
        _el(b"\xd7", _uint(block_track)),    # TrackNumber
        _el(b"\x73\xc5", _uint(block_track)),  # TrackUID
        _el(b"\x83", _uint(1)),              # TrackType: video
        _el(b"\x9c", _uint(0)),              # FlagLacing
        _el(b"\x86", b"V_MPEG4/ISO/AVC"),   # CodecID
        _el(b"\x63\xa2", _avcc(_SPS, _PPS)),  # CodecPrivate
        _el(b"\xe0", _el(b"\xb0", _uint(64)) + _el(b"\xba", _uint(64))),  # Video: 64x64
    ]))
    out = (
        header + b"\x18\x53\x80\x67" + b"\x01\xff\xff\xff\xff\xff\xff\xff"
        + info + _el(b"\x16\x54\xae\x6b", entries)
    )
    for frame, timecode in zip(frames, timecodes_ms):
        # AVCC frame: 4-byte length prefix + the NAL unit, as the CodecPrivate declares.
        sample = len(frame).to_bytes(4, "big") + frame
        block = (
            _vint(block_track)
            + (0).to_bytes(2, "big", signed=True)   # timecode relative to the Cluster
            + b"\x80"                               # flags: key frame
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


def _create_active_stream(ctx, kv, *, retention_hours=1):
    name = ctx.unique_name("sim2real-kvam-")
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
