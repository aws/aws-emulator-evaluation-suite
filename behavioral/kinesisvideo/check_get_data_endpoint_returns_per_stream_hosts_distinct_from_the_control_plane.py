"""get-data-endpoint-returns-per-stream-hosts-distinct-from-the-control-plane."""
from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import time
import urllib.parse

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "get-data-endpoint-returns-per-stream-hosts-distinct-from-the-control-plane"
GROUP = "media-data-plane"
SERVICES = ["kinesisvideo"]


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetDataEndpoint names hosts other than the control-plane host: PUT_MEDIA and GET_MEDIA share one, the
    archive APIs share a different one; media sent to the ingest host persists two fragments that the archive
    host lists for that stream only, while a second stream's archive stays empty."""

    kv = ctx.client("kinesisvideo")
    control_host = urllib.parse.urlparse(kv.meta.endpoint_url).netloc
    stream = _create_active_stream(ctx, kv)
    other = _create_active_stream(ctx, kv)

    ingest_apis = ("PUT_MEDIA", "GET_MEDIA")
    archive_apis = ("LIST_FRAGMENTS", "GET_MEDIA_FOR_FRAGMENT_LIST", "GET_CLIP")
    hosts = {
        api: urllib.parse.urlparse(_data_endpoint(kv, stream["name"], api)).netloc
        for api in ingest_apis + archive_apis
    }
    for api, host in hosts.items():
        assert host != control_host, (
            f"GetDataEndpoint({api}) returned the CONTROL host {host!r}; the data plane must "
            f"live on its own host"
        )
        assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", host), (
            f"GetDataEndpoint({api}) returned {host!r}, which is not a hostname"
        )
    ingest_hosts = {hosts[api] for api in ingest_apis}
    archive_hosts = {hosts[api] for api in archive_apis}
    assert len(ingest_hosts) == 1, f"the ingest APIs must share one host, got {hosts!r}"
    assert len(archive_hosts) == 1, f"the archive APIs must share one host, got {hosts!r}"
    assert ingest_hosts != archive_hosts, (
        f"ingest and archive must be different hosts, both were {ingest_hosts!r}"
    )

    marker = stream["name"].rsplit("-", 1)[-1].encode()
    frames = _frames(marker, 2)
    start = time.time()
    status, _headers, acks, tail = _put_media(
        ctx, kv, _data_endpoint(kv, stream["name"], "PUT_MEDIA"), stream["name"],
        _mkv(frames, [0, 1000]), start, expect_persisted=2,
    )
    assert status == 200, (
        f"the ingest host {sorted(ingest_hosts)!r} did not accept PutMedia: HTTP {status!r} "
        f"(tail {tail[:200]!r})"
    )
    persisted = _persisted(acks)
    assert len(persisted) == 2, (
        f"the discovered ingest host must really ingest: expected two PERSISTED fragments, "
        f"got {persisted!r}"
    )
    fragments = _await_fragments(ctx, kv, stream["name"], start - 60, start + 600, 2)
    assert {f["FragmentNumber"] for f in fragments} == set(persisted), (
        f"the archive host {sorted(archive_hosts)!r} does not see what the ingest host "
        f"accepted: {sorted(persisted)!r} vs {sorted(f['FragmentNumber'] for f in fragments)!r}"
    )
    assert not _list_fragments(ctx, kv, other["name"], start - 60, start + 600), (
        f"media sent to {stream['name']!r} appeared in the other stream "
        f"{other['name']!r}'s archive"
    )


_SOCKET_TIMEOUT_S = 25.0
_ACK_BUDGET_S = 60.0
_EBML_MAGIC = b"\x1a\x45\xdf\xa3"
_SEGMENT_ID = b"\x18\x53\x80\x67"
# A Segment of unknown size: what a live producer writes, because it cannot know the length.
_SEGMENT_UNKNOWN_SIZE = b"\x01\xff\xff\xff\xff\xff\xff\xff"
# An AVCDecoderConfigurationRecord (avcC) for 320x240 baseline H.264. KVS stores it as
# CodecPrivate and does not decode it on the ingest/archive path graded here.
_AVCC = bytes.fromhex("01420020ffe100086742c01e8c8d4d80010004680efa80")


def _create_active_stream(ctx, kv, *, retention_hours=1):
    """A stream this check owns, polled to ACTIVE. Retention is what makes fragments
    readable back through the archived-media APIs at all."""
    name = ctx.unique_name("sim2real-kv-")
    arn = kv.create_stream(
        StreamName=name,
        DataRetentionInHours=retention_hours,
        MediaType="video/h264",
        Tags={"sim2real": CHECK},
    )["StreamARN"]
    ctx.on_cleanup(lambda: kv.delete_stream(StreamARN=arn))
    deadline = time.monotonic() + 180.0
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_stream(StreamARN=arn)["StreamInfo"]["Status"]
        if status == "ACTIVE":
            return {"name": name, "arn": arn}
        time.sleep(2.0)
    raise AssertionError(f"stream {name!r} never reached ACTIVE (last status {status!r})")


def _data_endpoint(kv, stream_name, api_name):
    """The host AWS says to use for one API family. NOT the control-plane host: KVS mints a
    per-stream ingest host and a per-stream archive host, and a data call to the wrong one
    does not work."""
    endpoint = kv.get_data_endpoint(StreamName=stream_name, APIName=api_name)["DataEndpoint"]
    assert endpoint and "://" in endpoint, (
        f"GetDataEndpoint({api_name}) returned {endpoint!r}, not a URL"
    )
    return endpoint


# --- Matroska writer -----------------------------------------------------------------
# KVS ingests MKV and treats ONE Cluster as ONE fragment, so these bytes are the unit the
# whole data plane is expressed in. Hand-written rather than muxed by a tool: the point is
# to assert the exact frame bytes back out again.

def _vint(n):
    """An EBML variable-length integer (the marker bit is the length)."""
    for width in range(1, 9):
        if n < (1 << (7 * width)) - 1:
            return (n | (1 << (7 * width))).to_bytes(width, "big")
    raise AssertionError(f"{n!r} does not fit an EBML vint")


def _uint(n):
    return b"\x00" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")


def _el(element_id, payload):
    return element_id + _vint(len(payload)) + payload


def _mkv(frames, timecodes_ms, *, block_track=1, declared_tracks=(1,)):
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
    entries = b""
    for track_number in declared_tracks:
        entries += _el(b"\xae", b"".join([
            _el(b"\xd7", _uint(track_number)),   # TrackNumber
            _el(b"\x73\xc5", _uint(track_number)),  # TrackUID
            _el(b"\x83", _uint(1)),              # TrackType: video
            _el(b"\x9c", _uint(0)),              # FlagLacing
            _el(b"\x86", b"V_MPEG4/ISO/AVC"),   # CodecID
            _el(b"\x63\xa2", _AVCC),            # CodecPrivate
            _el(b"\xe0", _el(b"\xb0", _uint(320)) + _el(b"\xba", _uint(240))),  # Video
        ]))
    out = header + _SEGMENT_ID + _SEGMENT_UNKNOWN_SIZE + info + _el(b"\x16\x54\xae\x6b", entries)
    for frame, timecode in zip(frames, timecodes_ms):
        block = (
            _vint(block_track)
            + (0).to_bytes(2, "big", signed=True)   # timecode relative to the Cluster
            + b"\x80"                               # flags: key frame
            + frame
        )
        out += _el(b"\x1f\x43\xb6\x75", _el(b"\xe7", _uint(timecode)) + _el(b"\xa3", block))
    return out


def _frames(marker, count, *, size=320):
    """`count` distinguishable frame payloads, each carrying a marker unique to this run so
    the exact bytes can be recognised coming back out of the archive."""
    return [marker + b"-%d-" % i + bytes(size) for i in range(count)]


# --- PutMedia ------------------------------------------------------------------------

def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


def _put_media(ctx, kv, endpoint, stream_name, body, producer_start, *,
               timecode_type="RELATIVE", content_sha256="UNSIGNED-PAYLOAD",
               expect_persisted=0, path="/putMedia"):
    """PutMedia, hand-signed over raw HTTP, because there is no other way to make this call.

    PutMedia is absent from EVERY AWS SDK: it appears in no Smithy model (the kinesis-video
    model declares 32 operations and PutMedia is not one of them; `kinesis-video-media`
    declares only GetMedia), so boto3 cannot express it and the request has to be built and
    signed by hand against the per-stream ingest host GetDataEndpoint returned.

    Two things measured against real AWS shape this helper:

    * `x-amz-content-sha256` must be PRESENT and signed, or the request is refused
      403 InvalidSignatureException. Its value is not verified against the body -- signing
      the hash of b"" over a 900-byte body is accepted -- which is what makes the streaming
      form possible.
    * The response is HTTP 200 with a stream of JSON acknowledgements
      (BUFFERING -> RECEIVED -> PERSISTED per fragment), and an INGEST ERROR arrives IN BAND
      as an `{"EventType": "ERROR", "ErrorCode": ..., "ErrorId": ...}` acknowledgement on
      that same 200 response, not as an HTTP error.

    Returns (status, response_headers, acknowledgements, undecoded_tail).
    """
    parsed = urllib.parse.urlparse(ctx.endpoint_url(endpoint))
    host = parsed.netloc
    headers = {
        "x-amzn-stream-name": stream_name,
        "x-amzn-fragment-timecode-type": timecode_type,
        "x-amzn-producer-start-timestamp": f"{producer_start:.3f}",
        "Content-Type": "application/octet-stream",
    }
    if content_sha256 is not None:
        headers["x-amz-content-sha256"] = content_sha256
    request = AWSRequest(
        method="POST", url=f"{parsed.scheme}://{host}{path}", data=body, headers=headers
    )
    frozen = _frozen_credentials(kv)

    class _Auth(SigV4Auth):
        def payload(self, request):  # noqa: ARG002 - the header value IS the signed payload
            return content_sha256 if content_sha256 is not None else super().payload(request)

    _Auth(frozen, "kinesisvideo", ctx.region).add_auth(request)
    if parsed.scheme == "http":
        conn = http.client.HTTPConnection(host, timeout=_SOCKET_TIMEOUT_S)
    else:
        conn = http.client.HTTPSConnection(
            host, timeout=_SOCKET_TIMEOUT_S, context=_https_context(ctx.http_verify)
        )
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
    """The credentials this run signs with, taken from the client ctx built, never from the
    ambient credential chain."""
    raw = client._request_signer._credentials
    return raw.get_frozen_credentials() if hasattr(raw, "get_frozen_credentials") else raw


def _persisted(acks):
    """Fragment numbers acknowledged PERSISTED, in the order AWS acknowledged them."""
    return [a["FragmentNumber"] for a in acks if a.get("EventType") == "PERSISTED"]


def _ack_error(acks):
    for ack in acks:
        if ack.get("EventType") == "ERROR":
            return ack.get("ErrorCode"), ack.get("ErrorId")
    return None, None


def _amzn_error_type(response_headers):
    """The bare exception name out of `x-amzn-ErrorType`, which real AWS suffixes with a
    namespace after a colon (`InvalidSignatureException:<namespace>`)."""
    return (response_headers.get("x-amzn-errortype") or "").split(":", 1)[0]


def _list_fragments(ctx, kv, stream_name, start_ts, end_ts):
    """Every fragment in the window, paginated. Scoped to a stream this check created, so
    the result is a property of the query and not of who else is using the account."""
    client = ctx.client(
        "kinesis-video-archived-media",
        endpoint_url=_data_endpoint(kv, stream_name, "LIST_FRAGMENTS"),
    )
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


def _await_fragments(ctx, kv, stream_name, start_ts, end_ts, expect_count, *, budget_s=45.0):
    """Every fragment in the window, once at least `expect_count` of them are visible.

    PERSISTED is the ingest acknowledgement, not a promise that the archive index has caught
    up, so a bare ListFragments immediately after it is a race. This waits for the count the
    caller is entitled to and then returns whatever is actually there -- so the assertion that
    follows is still exact, and a wrong extra fragment still fails."""
    deadline = time.monotonic() + budget_s
    while True:
        fragments = _list_fragments(ctx, kv, stream_name, start_ts, end_ts)
        if len(fragments) >= expect_count or time.monotonic() >= deadline:
            return fragments
        time.sleep(2.0)


def _read_media(ctx, kv, stream_name, *, selector_type="EARLIEST"):
    """GetMedia through the per-stream ingest host, drained to bytes."""
    client = ctx.client(
        "kinesis-video-media", endpoint_url=_data_endpoint(kv, stream_name, "GET_MEDIA")
    )
    response = client.get_media(
        StreamName=stream_name, StartSelector={"StartSelectorType": selector_type}
    )
    payload = response["Payload"]
    try:
        return response, payload.read()
    finally:
        payload.close()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
