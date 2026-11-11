"""put-media-sequential-sessions-extend-stream-monotonically."""
from __future__ import annotations

import http.client
import json
import ssl
import struct
import time
import urllib.parse

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import Credentials

from behavioral_harness import tags

CHECK = "put-media-sequential-sessions-extend-stream-monotonically"
GROUP = "put-media"
SERVICES = ["kinesisvideo"]

_EBML_ID = {
    "EBML": b"\x1a\x45\xdf\xa3", "EBMLVersion": b"\x42\x86", "EBMLReadVersion": b"\x42\xf7",
    "EBMLMaxIDLength": b"\x42\xf2", "EBMLMaxSizeLength": b"\x42\xf3", "DocType": b"\x42\x82",
    "DocTypeVersion": b"\x42\x87", "DocTypeReadVersion": b"\x42\x85",
    "Segment": b"\x18\x53\x80\x67", "Info": b"\x15\x49\xa9\x66", "TimecodeScale": b"\x2a\xd7\xb1",
    "MuxingApp": b"\x4d\x80", "WritingApp": b"\x57\x41", "Tracks": b"\x16\x54\xae\x6b",
    "TrackEntry": b"\xae", "TrackNumber": b"\xd7", "TrackUID": b"\x73\xc5", "TrackType": b"\x83",
    "CodecID": b"\x86", "CodecPrivate": b"\x63\xa2", "Video": b"\xe0", "PixelWidth": b"\xb0",
    "PixelHeight": b"\xba", "Cluster": b"\x1f\x43\xb6\x75", "Timecode": b"\xe7",
    "SimpleBlock": b"\xa3",
}


#: A real 320x240 H.264 baseline AVCC CodecPrivate: one SPS plus one PPS.
_AVCC = bytes.fromhex("014d400bffe1000e674d400b9a6a0203f2ff0080004601000468ce3c80")


#: Milliseconds between the SimpleBlocks inside one cluster. A fragment holding N blocks
#: therefore spans (N - 1) * _FRAME_SPACING_MS, which is what ListFragments must report.
_FRAME_SPACING_MS = 40


def _vint(value):
    """An EBML variable-size integer: the shortest encoding that leaves room for the marker bit."""
    length = 1
    while value >= (1 << (7 * length)) - 1:
        length += 1
    out = bytearray(value.to_bytes(length, "big"))
    out[0] |= 1 << (8 - length)
    return bytes(out)


def _uint(value):
    return b"\x00" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


def _el(name, data):
    return _EBML_ID[name] + _vint(len(data)) + data


def _simple_block(track_number, relative_ms, frame):
    return _el("SimpleBlock",
               _vint(track_number) + struct.pack(">h", relative_ms) + b"\x80" + frame)


def _cluster(timecode_ms, blocks):
    """One Matroska Cluster == one KVS fragment."""
    return _el("Cluster", _el("Timecode", _uint(timecode_ms)) + b"".join(blocks))


def _mkv_header(doctype="matroska"):
    return _el("EBML",
               _el("EBMLVersion", _uint(1)) + _el("EBMLReadVersion", _uint(1))
               + _el("EBMLMaxIDLength", _uint(4)) + _el("EBMLMaxSizeLength", _uint(8))
               + _el("DocType", doctype.encode()) + _el("DocTypeVersion", _uint(2))
               + _el("DocTypeReadVersion", _uint(2)))


def _mkv_info():
    return _el("Info",
               _el("TimecodeScale", _uint(1000000)) + _el("MuxingApp", b"sim2real")
               + _el("WritingApp", b"sim2real"))


def _mkv_tracks(track_number=1):
    entry = (_el("TrackNumber", _uint(track_number)) + _el("TrackUID", _uint(track_number))
             + _el("TrackType", _uint(1)) + _el("CodecID", b"V_MPEG4/ISO/AVC")
             + _el("CodecPrivate", _AVCC)
             + _el("Video", _el("PixelWidth", _uint(320)) + _el("PixelHeight", _uint(240))))
    return _el("Tracks", _el("TrackEntry", entry))


def _mkv_stream(fragments, *, doctype="matroska", block_track_number=1, with_tracks=True):
    """Build a Matroska document. ``fragments`` is [(cluster_timecode_ms, [frame_bytes, ...])]."""
    body = _mkv_info() + (_mkv_tracks() if with_tracks else b"")
    for timecode_ms, frames in fragments:
        body += _cluster(timecode_ms, [_simple_block(block_track_number,
                                                     i * _FRAME_SPACING_MS, frame)
                                       for i, frame in enumerate(frames)])
    return _mkv_header(doctype) + _el("Segment", body)


def _frames(tag, count, size=60):
    """Frame payloads that are unique per (tag, index) — so GetMedia output can be checked byte for byte."""
    return [("%s%02d-" % (tag, i)).encode() + bytes([0x41 + (i % 26)]) * size
            for i in range(count)]


class _UnsignedPayloadSigV4(SigV4Auth):
    """SigV4 over ``UNSIGNED-PAYLOAD``, which is what the PutMedia ingest front end verifies.

    Measured against real AWS: signing the true sha256 of the body is rejected
    InvalidSignatureException, because the front end never buffers the stream it is being handed.
    """

    def payload(self, request):
        return "UNSIGNED-PAYLOAD"


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


def _put_media(ctx, data_endpoint, body, *, stream_name=None, stream_arn=None,
               timecode_type="RELATIVE", producer_start_ts=None, omit=(), timeout=120.0):
    """POST /putMedia to a GetDataEndpoint host over raw HTTPS. -> (status, ErrorType, bytes).

    PutMedia is in no AWS SDK model — ``boto3.client("kinesisvideo")`` has no ``put_media`` and
    ``com.amazonaws.kinesisvideomedia`` declares GetMedia only — so reaching this data plane means
    building and signing the request by hand against the host the control plane handed us. The body
    goes out ``Transfer-Encoding: chunked``, so Content-Length is neither signed nor sent.
    """
    env = ctx.subprocess_env()  # this run's credentials for the subprocess; never exported
    credentials = Credentials(env["AWS_ACCESS_KEY_ID"], env["AWS_SECRET_ACCESS_KEY"],
                              env.get("AWS_SESSION_TOKEN"))
    split = urllib.parse.urlsplit(ctx.endpoint_url(data_endpoint))
    headers = {"Host": split.netloc, "x-amzn-fragment-timecode-type": timecode_type,
               "x-amz-content-sha256": "UNSIGNED-PAYLOAD"}
    if stream_name is not None:
        headers["x-amzn-stream-name"] = stream_name
    if stream_arn is not None:
        headers["x-amzn-stream-arn"] = stream_arn
    if producer_start_ts is not None:
        headers["x-amzn-producer-start-timestamp"] = "%.3f" % producer_start_ts
    for header in omit:
        headers.pop(header, None)

    request = AWSRequest(method="POST", url="%s://%s/putMedia" % (split.scheme, split.netloc),
                        data=body, headers=headers)
    _UnsignedPayloadSigV4(credentials, "kinesisvideo", ctx.region).add_auth(request)
    signed = dict(request.headers)
    signed.pop("Content-Length", None)

    if split.scheme == "https":
        conn = http.client.HTTPSConnection(split.netloc, timeout=timeout,
                                           context=_https_context(ctx.http_verify))
    else:
        conn = http.client.HTTPConnection(split.netloc, timeout=timeout)
    try:
        conn.putrequest("POST", "/putMedia", skip_host=True, skip_accept_encoding=True)
        for key, value in signed.items():
            conn.putheader(key, value)
        conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()
        for offset in range(0, len(body), 8192):
            chunk = body[offset:offset + 8192]
            conn.send(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
        conn.send(b"0\r\n\r\n")
        response = conn.getresponse()
        return response.status, response.getheader("x-amzn-ErrorType"), response.read()
    finally:
        conn.close()


def _acks(raw):
    """PutMedia answers with newline-delimited Acknowledgement JSON objects, not one document."""
    decoder = json.JSONDecoder()
    out, text, pos = [], raw.decode("utf-8", "replace"), 0
    while pos < len(text):
        while pos < len(text) and text[pos] in " \r\n\t":
            pos += 1
        if pos >= len(text):
            break
        obj, pos = decoder.raw_decode(text, pos)
        out.append(obj)
    return out


def _persisted_fragment_numbers(ctx, stream, fragments, **kw):
    """PutMedia ``fragments`` and return the PERSISTED FragmentNumbers, in ack order."""
    status, error_type, raw = _put_media(ctx, stream["put_endpoint"], _mkv_stream(fragments),
                                         stream_name=stream["name"], **kw)
    assert status == 200, ("PutMedia answered HTTP %s (x-amzn-ErrorType %r): %r"
                           % (status, error_type, raw[:400]))
    acks = _acks(raw)
    errored = [a for a in acks if a.get("EventType") == "ERROR"]
    assert not errored, "PutMedia returned ERROR acknowledgements: %r" % (errored,)
    persisted = [a["FragmentNumber"] for a in acks if a.get("EventType") == "PERSISTED"]
    assert len(persisted) == len(fragments), (
        "expected one PERSISTED ack per ingested cluster (%d), got %d; acks were %r"
        % (len(fragments), len(persisted), acks))
    return persisted


def _poll(probe, accept, *, timeout_s, interval_s, what):
    """Poll an observable condition. Never a bare sleep standing in for a wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        observed = probe()
        if accept(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError("%s not observed within %.0fs; last read %r"
                                 % (what, timeout_s, observed))
        time.sleep(interval_s)


def _active_stream(ctx, *, retention_hours=1, media_type="video/h264"):
    """A Kinesis Video stream this check created, ACTIVE, with its discovered data endpoints."""
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kv-")
    arn = kv.create_stream(StreamName=name, DataRetentionInHours=retention_hours,
                           MediaType=media_type, Tags={"sim2real": CHECK})["StreamARN"]
    ctx.on_cleanup(lambda: kv.delete_stream(StreamARN=arn))
    status = _poll(lambda: kv.describe_stream(StreamName=name)["StreamInfo"]["Status"],
                   lambda s: s == "ACTIVE", timeout_s=90, interval_s=3,
                   what="stream %s reaching ACTIVE" % name)
    assert status == "ACTIVE", "stream %s is %r, not ACTIVE" % (name, status)
    return {
        "name": name,
        "arn": arn,
        "put_endpoint": kv.get_data_endpoint(StreamName=name,
                                             APIName="PUT_MEDIA")["DataEndpoint"],
        "get_endpoint": kv.get_data_endpoint(StreamName=name,
                                            APIName="GET_MEDIA")["DataEndpoint"],
        "list_endpoint": kv.get_data_endpoint(StreamName=name,
                                              APIName="LIST_FRAGMENTS")["DataEndpoint"],
    }


def _get_media(ctx, stream, start_selector, *, limit=4194304):
    """GetMedia on the discovered data endpoint. -> (response, payload bytes)."""
    client = ctx.client("kinesis-video-media", endpoint_url=stream["get_endpoint"],
                        config=Config(read_timeout=40, connect_timeout=15,
                                      retries={"max_attempts": 1}))
    response = client.get_media(StreamName=stream["name"], StartSelector=start_selector)
    return response, response["Payload"].read(limit)


def _list_fragments(ctx, stream, *, window_s=1800):
    """Every archived fragment of THIS stream, paginated, sorted by fragment number.

    Scoped to one stream this check created, so "exactly these" is a property of the query rather
    than of what else is running in the shared account. Sorted because ListFragments does not
    return fragments in any order — measured against real AWS, which interleaved them.
    """
    client = ctx.client("kinesis-video-archived-media", endpoint_url=stream["list_endpoint"])
    now = time.time()
    selector = {"FragmentSelectorType": "SERVER_TIMESTAMP",
                "TimestampRange": {"StartTimestamp": now - window_s,
                                   "EndTimestamp": now + window_s}}
    out = []
    for page in client.get_paginator("list_fragments").paginate(
            StreamName=stream["name"], FragmentSelector=selector,
            PaginationConfig={"PageSize": 100}):
        out.extend(page.get("Fragments", []))
    return sorted(out, key=lambda f: int(f["FragmentNumber"]))


@tags("axis:happy-path", "cap:c2", "cap:c6", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx):
    """A second PutMedia session whose cluster timecode restarts at 0 gets a higher fragment number than the
    first; ListFragments lists both sessions' fragments, and GetMedia EARLIEST returns the frames of both."""
    stream = _active_stream(ctx)
    first_frames = _frames("S1", 4)
    second_frames = _frames("S2", 4)

    first = _persisted_fragment_numbers(ctx, stream, [(0, first_frames)],
                                        producer_start_ts=time.time() - 10)
    second = _persisted_fragment_numbers(ctx, stream, [(0, second_frames)],
                                         producer_start_ts=time.time() - 4)
    # Cluster timecodes are scoped to their session, so restarting at 0 is not a regression.
    assert int(second[0]) > int(first[0]), (
        "a later session must extend the stream, so its fragment number has to exceed the "
        "earlier one: %s against %s" % (second[0], first[0]))

    listed = _poll(lambda: _list_fragments(ctx, stream), lambda found: len(found) >= 2,
                   timeout_s=90, interval_s=5,
                   what="both sessions' fragments becoming listable")
    assert [f["FragmentNumber"] for f in listed] == sorted(first + second, key=int), (
        "the archive must hold both sessions' fragments and nothing else, it holds %r"
        % ([f["FragmentNumber"] for f in listed],))

    _, payload = _get_media(ctx, stream, {"StartSelectorType": "EARLIEST"})
    for label, group in (("first", first_frames), ("second", second_frames)):
        for position, frame in enumerate(group):
            assert frame in payload, (
                "one read of the stream must carry both sessions, but frame %d of the %s "
                "session is absent from the %d bytes returned"
                % (position, label, len(payload)))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
