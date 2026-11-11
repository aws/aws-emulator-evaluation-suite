"""test-event-pattern-cidr-matcher-boundaries."""

from __future__ import annotations

import ipaddress
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-event-pattern-cidr-matcher-boundaries"
GROUP = "test-event-pattern"
SERVICES = ["events"]


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "plane:control")
def run(ctx) -> None:
    """`cidr` is inclusive prefix containment for IPv4 and IPv6 (expected verdicts from ipaddress), a
    mask equal to the address width is refused, and wrong-family, non-IP and empty-array values miss.
    """
    events = ctx.client("events")

    for cidr in ("10.0.0.0/24", "192.168.5.0/30", "172.16.0.0/12", "2001:db8:abcd:12::/64"):
        net = ipaddress.ip_network(cidr)
        first, last = net.network_address, net.broadcast_address
        middle = ipaddress.ip_address(int(first) + (int(last) - int(first)) // 2)
        below = ipaddress.ip_address(int(first) - 1)
        above = ipaddress.ip_address(int(last) + 1)

        # Sanity on the derivation itself, so a bug in this file cannot masquerade as a target bug.
        assert first in net and last in net and middle in net, (
            f"derivation error: {first}/{middle}/{last} must all be inside {cidr}"
        )
        assert below not in net and above not in net, (
            f"derivation error: {below} and {above} must both be outside {cidr}"
        )

        for addr in (first, middle, last):
            _expect(
                events,
                {"detail": {"sourceIPAddress": [{"cidr": cidr}]}},
                {"sourceIPAddress": str(addr)},
                True,
                f"{addr} is inside {cidr} (ipaddress says so), so cidr must match it",
            )
        for addr in (below, above):
            _expect(
                events,
                {"detail": {"sourceIPAddress": [{"cidr": cidr}]}},
                {"sourceIPAddress": str(addr)},
                False,
                f"{addr} is one address outside {cidr}, so cidr must NOT match it — a string-prefix "
                f"implementation of cidr gets exactly this wrong",
            )

    # AWS refuses a mask equal to the address width (/32, /128) although ipaddress accepts it;
    # the width - 1 mask is the positive control.
    _expect(
        events,
        {"detail": {"sourceIPAddress": [{"cidr": "203.0.113.0/31"}]}},
        {"sourceIPAddress": "203.0.113.1"},
        True,
        "positive control: the narrowest VALID IPv4 mask (/31, one below the address width) "
        "still evaluates a real match",
    )
    ipv4_full_mask_err = _client_error(
        events, {"detail": {"sourceIPAddress": [{"cidr": "203.0.113.0/32"}]}}
    )
    assert ipv4_full_mask_err.get("Code") == "InvalidEventPatternException", (
        f"an IPv4 cidr mask equal to the address width (/32) must be refused as a malformed "
        f"pattern, got {ipv4_full_mask_err}"
    )
    assert ipv4_full_mask_err.get("Message") == (
        "Event pattern is not valid. Reason: IPv4 mask bits must be < 32"
    ), f"unexpected message for the /32 refusal: {ipv4_full_mask_err.get('Message')!r}"

    _expect(
        events,
        {"detail": {"sourceIPAddress": [{"cidr": "2001:db8::/127"}]}},
        {"sourceIPAddress": "2001:db8::1"},
        True,
        "positive control: the narrowest VALID IPv6 mask (/127, one below the address width) "
        "still evaluates a real match",
    )
    ipv6_full_mask_err = _client_error(
        events, {"detail": {"sourceIPAddress": [{"cidr": "2001:db8::/128"}]}}
    )
    assert ipv6_full_mask_err.get("Code") == "InvalidEventPatternException", (
        f"an IPv6 cidr mask equal to the address width (/128) must be refused as a malformed "
        f"pattern, got {ipv6_full_mask_err}"
    )
    assert ipv6_full_mask_err.get("Message") == (
        "Event pattern is not valid. Reason: IPv6 mask bits must be < 128"
    ), f"unexpected message for the /128 refusal: {ipv6_full_mask_err.get('Message')!r}"

    # --- cross-family: an address of the wrong family is never inside the prefix. ---
    _expect(
        events,
        {"detail": {"sourceIPAddress": [{"cidr": "10.0.0.0/8"}]}},
        {"sourceIPAddress": "2001:db8::1"},
        False,
        "an IPv6 address cannot be inside an IPv4 prefix",
    )
    _expect(
        events,
        {"detail": {"sourceIPAddress": [{"cidr": "2001:db8::/32"}]}},
        {"sourceIPAddress": "10.0.0.1"},
        False,
        "an IPv4 address cannot be inside an IPv6 prefix",
    )

    # --- not an IP address at all. ---
    for junk in ("not-an-ip", "10.0.0.256", "10.0.0", ""):
        _expect(
            events,
            {"detail": {"sourceIPAddress": [{"cidr": "10.0.0.0/24"}]}},
            {"sourceIPAddress": junk},
            False,
            f"{junk!r} is not an IP address, so no prefix can contain it",
        )

    # --- the array-join rule extends to cidr: SOME element inside is a match, none is not. ---
    _expect(
        events,
        {"detail": {"sourceIPAddress": [{"cidr": "10.0.0.0/24"}]}},
        {"sourceIPAddress": ["203.0.113.9", "10.0.0.7"]},
        True,
        "one element of the event's array is inside the prefix, which matches",
    )
    _expect(
        events,
        {"detail": {"sourceIPAddress": [{"cidr": "10.0.0.0/24"}]}},
        {"sourceIPAddress": ["203.0.113.9", "10.0.1.7"]},
        False,
        "no element of the event's array is inside the prefix, so nothing matches",
    )
    _expect(
        events,
        {"detail": {"sourceIPAddress": [{"cidr": "10.0.0.0/24"}]}},
        {"sourceIPAddress": []},
        False,
        "an empty event array cannot satisfy a cidr operand",
    )

    # --- a cidr operand is one of several keys in a pattern: the other keys still AND. ---
    both_keys = {
        "detail": {
            "sourceIPAddress": [{"cidr": "10.0.0.0/24"}],
            "eventName": ["PutObject"],
        }
    }
    _expect(
        events,
        both_keys,
        {"sourceIPAddress": "10.0.0.7", "eventName": "PutObject"},
        True,
        "both keys satisfied",
    )
    _expect(
        events,
        both_keys,
        {"sourceIPAddress": "10.0.0.7", "eventName": "GetObject"},
        False,
        "the cidr key matches but the sibling key does not — multiple keys are AND",
    )


def _envelope(detail: dict) -> dict:
    """A complete EventBridge envelope carrying `detail`; account and region are placeholders
    because TestEventPattern never touches either."""
    return {
        "id": "00000000-0000-0000-0000-000000000000",
        "detail-type": "CidrProbe",
        "source": "sim2real.cidr",
        "account": "123456789012",
        "time": "2020-01-01T00:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": detail,
    }


def _matches(events, pattern: dict, detail: dict) -> bool:
    """TestEventPattern's boolean verdict for one (pattern, event) pair."""
    resp = events.test_event_pattern(
        EventPattern=json.dumps(pattern), Event=json.dumps(_envelope(detail))
    )
    result = resp["Result"]
    assert isinstance(result, bool), (
        f"TestEventPattern.Result must be a JSON boolean, got {result!r} "
        f"({type(result).__name__}) for pattern {json.dumps(pattern)}"
    )
    return result


def _client_error(events, pattern: dict) -> dict:
    """The botocore Error dict TestEventPattern raises for `pattern`; an unexpected success raises."""
    try:
        result = events.test_event_pattern(
            EventPattern=json.dumps(pattern), Event=json.dumps(_envelope({"sourceIPAddress": "1.2.3.4"}))
        )
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"TestEventPattern accepted {json.dumps(pattern)} and returned {result!r}; AWS refuses it"
    )


def _expect(events, pattern: dict, detail: dict, want: bool, why: str) -> None:
    """Assert TestEventPattern's verdict, naming the pattern and event that disagreed."""
    got = _matches(events, pattern, detail)
    assert got is want, (
        f"cidr verdict wrong: expected {want}, got {got}. {why}\n"
        f"  pattern = {json.dumps(pattern)}\n"
        f"  detail  = {json.dumps(detail)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
