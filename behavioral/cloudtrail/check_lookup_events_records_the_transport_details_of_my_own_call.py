"""lookup-events-records-the-transport-details-of-my-own-call."""

from __future__ import annotations

import datetime
import ipaddress
import json
import re
import time
from urllib.parse import urlsplit

import botocore
from botocore.config import Config

from behavioral_harness import tags

CHECK = "lookup-events-records-the-transport-details-of-my-own-call"
GROUP = "data-plane"
SERVICES = ["cloudtrail"]

# Marks a data-plane failure so it reads as a fidelity failure rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_INDEX_BUDGET_S = 255.0  # CloudTrail indexes a new event in roughly 80-136 s
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

_TLS_VERSION_RE = re.compile(r"^TLSv1\.(\d+)$")

# ===== helpers =====


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded)."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    return out


def _is_ip_address(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _find(events, token):
    for ev in events:
        if token in ev.get("CloudTrailEvent", ""):
            return ev
    return None


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """CloudTrail records the transport of the caller's own request -- the User-Agent header the
    client actually sent, the source address, and the TLS details -- not a template.
    """
    ct = ctx.client("cloudtrail")

    ua_token = f"sim2realbehavua-{ctx.unique_name('').lower()}"
    plain_token_1 = ctx.unique_name("sim2realctuaplain1").lower()
    plain_token_2 = ctx.unique_name("sim2realctuaplain2").lower()
    marked_token = ctx.unique_name("sim2realctuamarked").lower()

    # `config=` is merged over the runner's base config by ctx.client, so the retry, endpoint and
    # TLS wiring is preserved and only the User-Agent suffix changes.
    ct_marked = ctx.client("cloudtrail", config=Config(user_agent_extra=ua_token))

    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    ct.describe_trails(trailNameList=[plain_token_1])
    ct_marked.describe_trails(trailNameList=[marked_token])
    ct.describe_trails(trailNameList=[plain_token_2])

    # The endpoint the assertions below are derived from. Read off the client so it follows the
    # target: on real AWS this is cloudtrail.<region>.amazonaws.com, on an emulator it is
    # whatever host the runner pointed at. Transport only -- no assertion is forked on it.
    expected_host = urlsplit(ct.meta.endpoint_url).hostname
    assert expected_host, (
        f"could not derive a host from the cloudtrail client's endpoint_url "
        f"{ct.meta.endpoint_url!r}; the clientProvidedHostHeader assertion has no expected value"
    )

    window_start = emitted_at - datetime.timedelta(minutes=2)
    found: dict[str, dict] = {}
    polls = 0
    scanned = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        events = _lookup_all(
            ct,
            StartTime=window_start,
            EndTime=datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=5),
            MaxResults=50,
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}
            ],
        )
        scanned = len(events)
        for label, token in (
            ("plain1", plain_token_1), ("marked", marked_token), ("plain2", plain_token_2),
        ):
            if label not in found:
                hit = _find(events, token)
                if hit is not None:
                    found[label] = hit
        if len(found) == 3:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert len(found) == 3, (
        f"{DATAPLANE_MARKER}: event history did not return all three of this check's own calls. "
        f"Found {sorted(found)!r} after {polls} polls over {waited:.0f}s scanning {scanned} "
        f"DescribeTrails events; the markers were {plain_token_1!r}, {marked_token!r}, "
        f"{plain_token_2!r}, all made at about {emitted_at.isoformat()}. Real AWS indexed markers "
        f"of this shape in 80-136s."
    )

    records = {label: json.loads(ev["CloudTrailEvent"]) for label, ev in found.items()}

    # --- the User-Agent header the client sent is what got recorded.
    marked_ua = records["marked"]["userAgent"]
    assert ua_token in marked_ua, (
        f"the run-unique User-Agent fragment {ua_token!r} was sent in the User-Agent header of "
        f"exactly one of three otherwise identical DescribeTrails calls, and the audit record "
        f"for that call reports userAgent={marked_ua!r} -- the fragment is absent. A target that "
        f"reconstructs the record from the parsed request rather than from the request as it "
        f"arrived cannot carry it"
    )
    for label in ("plain1", "plain2"):
        other_ua = records[label]["userAgent"]
        assert ua_token not in other_ua, (
            f"the User-Agent fragment {ua_token!r} was sent on only ONE call, but the record for "
            f"marker {label!r} also reports it: userAgent={other_ua!r}. A target that copies one "
            f"observed UA onto every record in the batch fails here"
        )
    assert records["plain1"]["userAgent"] == records["plain2"]["userAgent"], (
        f"two calls made by the SAME client seconds apart were audited with different "
        f"userAgent values: {records['plain1']['userAgent']!r} vs "
        f"{records['plain2']['userAgent']!r}"
    )

    # --- it is this process's SDK, not a plausible constant.
    for label in ("plain1", "marked", "plain2"):
        ua = records[label]["userAgent"]
        assert botocore.__version__ in ua, (
            f"marker {label!r}: userAgent={ua!r} does not contain this process's botocore "
            f"version ({botocore.__version__!r}). The recorded UA must describe the client that "
            f"actually made the call"
        )

    # --- one caller, one source address, and not a service-invoked form.
    ips = {label: records[label]["sourceIPAddress"] for label in records}
    assert len(set(ips.values())) == 1, (
        f"three calls from one process in one run were audited with different sourceIPAddress "
        f"values: {ips!r}"
    )
    source_ip = next(iter(ips.values()))
    assert source_ip, f"sourceIPAddress is empty: {ips!r}"
    assert _is_ip_address(source_ip), (
        f"sourceIPAddress is {source_ip!r}, not an IP address. Real AWS records a service "
        f"principal there only when a SERVICE made the call on the caller's behalf; these three "
        f"calls were made directly by this process with its own credentials"
    )
    assert source_ip != "AWS Internal", (
        f"sourceIPAddress is the literal {source_ip!r}, which real AWS uses for internal "
        f"activity, not for a direct signed call from a customer principal"
    )

    # --- the TLS details of the connection this process opened.
    for label in ("plain1", "marked", "plain2"):
        record = records[label]
        assert "tlsDetails" in record, (
            f"marker {label!r}: the audit record has no tlsDetails member. Members present: "
            f"{sorted(record)!r}; a CloudTrail record of a direct call over TLS carries the "
            f"connection's tlsDetails"
        )
        tls = record["tlsDetails"]
        assert tls["clientProvidedHostHeader"] == expected_host, (
            f"marker {label!r}: tlsDetails.clientProvidedHostHeader is "
            f"{tls.get('clientProvidedHostHeader')!r}, expected the host this check's own client "
            f"addressed ({expected_host!r}, from endpoint_url {ct.meta.endpoint_url!r}). The "
            f"member records the Host header the CLIENT chose, so it follows the target"
        )
        match = _TLS_VERSION_RE.match(tls["tlsVersion"])
        assert match is not None, (
            f"marker {label!r}: tlsDetails.tlsVersion is {tls.get('tlsVersion')!r}, which is not "
            f"of the form TLSv1.<minor>"
        )
        assert int(match.group(1)) >= 2, (
            f"marker {label!r}: tlsDetails.tlsVersion is {tls['tlsVersion']!r}; a current SDK "
            f"negotiates TLS 1.2 or better, so a recorded 1.0/1.1 means the member is not "
            f"describing this connection"
        )
        assert tls["cipherSuite"], (
            f"marker {label!r}: tlsDetails.cipherSuite is {tls.get('cipherSuite')!r}; a "
            f"negotiated TLS connection has a cipher suite"
        )

    # --- The envelope and the payload agree on which call each record is about, so none of the
    # above is being read off the wrong event.
    for label in records:
        assert found[label]["EventId"] == records[label]["eventID"], (
            f"marker {label!r}: envelope EventId {found[label]['EventId']!r} disagrees with the "
            f"embedded record's eventID {records[label].get('eventID')!r}"
        )
    assert len({found[label]["EventId"] for label in found}) == 3, (
        f"the three calls were assigned only "
        f"{len({found[label]['EventId'] for label in found})} distinct EventIds: "
        f"{ {label: found[label]['EventId'] for label in found} !r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
