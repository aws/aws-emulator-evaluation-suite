"""get-media-by-stream-arn-returns-ingested-fragment."""
from __future__ import annotations

import http.client
import json
import socket
import time
import urllib.parse

from botocore.auth import SigV4Auth
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-media-by-stream-arn-returns-ingested-fragment"
GROUP = "data-plane"
SERVICES = ["kinesis-video-media"]

_MEDIA_CONFIG = Config(read_timeout=40, connect_timeout=15, retries={"max_attempts": 1})
_EBML_MAGIC = b"\x1a\x45\xdf\xa3"
# A real 320x240 H.264 baseline AVCC CodecPrivate (one SPS plus one PPS).
_AVCC = bytes.fromhex("014d400bffe1000e674d400b9a6a0203f2ff0080004601000468ce3c80")
_SOCKET_TIMEOUT_S = 25.0
_ACK_BUDGET_S = 60.0


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A frame sent through PutMedia is PERSISTED as a fragment, and GetMedia addressed purely by
    StreamARN (never StreamName) returns a Matroska document carrying that exact frame byte for
    byte."""
    kv = ctx.client("kinesisvideo")
    stream = _create_active_stream(ctx, kv)
    marker = stream["name"].rsplit("-", 1)[-1].encode()
    frame = marker + b"-frame-" + bytes(256)

    put_endpoint = _data_endpoint(kv, stream["arn"], "PUT_MEDIA")
    status, headers, acks, tail = _put_media(
        ctx, kv, put_endpoint, stream["arn"], _mkv([frame], [0])
    )
    assert status == 200, f"PutMedia expected HTTP 200, got {status!r} (tail {tail[:200]!r})"
    assert _ack_error(acks) == (None, None), (
        f"PutMedia of a valid container reported an ingest error: {_ack_error(acks)!r}"
    )
    persisted = [a["FragmentNumber"] for a in acks if a.get("EventType") == "PERSISTED"]
    assert len(persisted) == 1, (
        f"one Cluster must persist as one fragment, got PERSISTED acks {persisted!r} from {acks!r}"
    )

    get_endpoint = _data_endpoint(kv, stream["arn"], "GET_MEDIA")
    media = ctx.client(
        "kinesis-video-media", endpoint_url=ctx.endpoint_url(get_endpoint), config=_MEDIA_CONFIG
    )
    response = media.get_media(
        StreamARN=stream["arn"], StartSelector={"StartSelectorType": "EARLIEST"}
    )
    read_status = response["ResponseMetadata"]["HTTPStatusCode"]
    assert read_status == 200, f"expected GetMedia(StreamARN=...) 200, got {read_status}"
    content_type = response["ContentType"]
    assert content_type == "video/webm", f"expected ContentType video/webm, got {content_type!r}"

    payload = response["Payload"]
    try:
        data = payload.read()
    finally:
        payload.close()
    assert data[:4] == _EBML_MAGIC, (
        f"GetMedia must serve Matroska: expected EBML magic {_EBML_MAGIC!r}, got {data[:8]!r}"
    )
    assert frame in data, (
        f"the frame persisted as fragment {persisted[0]!r} is absent from the "
        f"{len(data)} bytes GetMedia(StreamARN=...) served"
    )


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=3.0, what="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} not met within {timeout_s}s (last={last!r})")


def _create_active_stream(ctx, kv, *, retention_hours=1):
    name = ctx.unique_name("sim2real-behav-kvm-")
    arn = kv.create_stream(
        StreamName=name,
        DataRetentionInHours=retention_hours,
        MediaType="video/h264",
        Tags={"sim2real": CHECK},
    )["StreamARN"]

    def _cleanup():
        try:
            kv.delete_stream(StreamARN=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    status = _poll_until(
        lambda: kv.describe_stream(StreamARN=arn)["StreamInfo"]["Status"],
        lambda s: s == "ACTIVE",
        what=f"stream {name!r} reaching ACTIVE",
    )
    assert status == "ACTIVE", f"stream {name!r} is {status!r}, not ACTIVE"
    return {"name": name, "arn": arn}


def _data_endpoint(kv, stream_arn, api_name):
    endpoint = kv.get_data_endpoint(StreamARN=stream_arn, APIName=api_name)["DataEndpoint"]
    assert endpoint and "://" in endpoint, (
        f"GetDataEndpoint({api_name}) returned {endpoint!r}, not a URL"
    )
    return endpoint


# --- Matroska writer -----------------------------------------------------------------
# KVS ingests MKV and treats ONE Cluster as ONE fragment; this is hand-written rather than
# muxed by a tool because the point is to assert the exact frame bytes back out again.

def _vint(n):
    for width in range(1, 9):
        if n < (1 << (7 * width)) - 1:
            return (n | (1 << (7 * width))).to_bytes(width, "big")
    raise AssertionError(f"{n!r} does not fit an EBML vint")


def _uint(n):
    return b"\x00" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")


def _el(element_id, payload):
    return element_id + _vint(len(payload)) + payload


def _mkv(frames, timecodes_ms, *, track_number=1):
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
    track_entry = _el(b"\xae", b"".join([
        _el(b"\xd7", _uint(track_number)),
        _el(b"\x73\xc5", _uint(track_number)),
        _el(b"\x83", _uint(1)),
        _el(b"\x9c", _uint(0)),
        _el(b"\x86", b"V_MPEG4/ISO/AVC"),
        _el(b"\x63\xa2", _AVCC),
        _el(b"\xe0", _el(b"\xb0", _uint(320)) + _el(b"\xba", _uint(240))),
    ]))
    out = header + b"\x18\x53\x80\x67" + b"\x01\xff\xff\xff\xff\xff\xff\xff"
    out += info + _el(b"\x16\x54\xae\x6b", track_entry)
    for frame, timecode in zip(frames, timecodes_ms):
        block = (
            _vint(track_number)
            + (0).to_bytes(2, "big", signed=True)
            + b"\x80"
            + frame
        )
        out += _el(b"\x1f\x43\xb6\x75", _el(b"\xe7", _uint(timecode)) + _el(b"\xa3", block))
    return out


# --- PutMedia --------------------------------------------------------------------------
# PutMedia appears in no AWS SDK model -- `com.amazonaws.kinesisvideomedia` declares GetMedia
# only -- so reaching it means building and signing the request by hand against the per-stream
# ingest host GetDataEndpoint returned.

def _put_media(ctx, kv, endpoint, stream_arn, body, *, path="/putMedia"):
    """POST /putMedia over raw HTTP(S). -> (status, response_headers, acks, undecoded_tail)."""
    parsed = urllib.parse.urlparse(ctx.endpoint_url(endpoint))
    host = parsed.netloc
    headers = {
        "x-amzn-stream-arn": stream_arn,
        "x-amzn-fragment-timecode-type": "RELATIVE",
        "x-amzn-producer-start-timestamp": f"{time.time():.3f}",
        "Content-Type": "application/octet-stream",
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }

    class _Auth(SigV4Auth):
        def payload(self, request):
            return "UNSIGNED-PAYLOAD"

    from botocore.awsrequest import AWSRequest

    request = AWSRequest(
        method="POST", url=f"{parsed.scheme}://{host}{path}", data=body, headers=headers
    )
    frozen = _frozen_credentials(kv)
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
            if any(a.get("EventType") == "PERSISTED" for a in acks):
                break
        return status, response_headers, acks, buf
    finally:
        conn.close()


def _frozen_credentials(client):
    raw = client._request_signer._credentials
    return raw.get_frozen_credentials() if hasattr(raw, "get_frozen_credentials") else raw


def _ack_error(acks):
    for ack in acks:
        if ack.get("EventType") == "ERROR":
            return ack.get("ErrorCode"), ack.get("ErrorId")
    return None, None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
