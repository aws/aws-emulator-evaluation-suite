"""op-contract-describe-traffic-mirror-sessions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-traffic-mirror-sessions"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTrafficMirrorSessions answers with a list; a session-id filter for an absent session and
    an unrecognized filter name match nothing, and naming that session in TrafficMirrorSessionIds
    fails with InvalidTrafficMirrorSessionId.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_traffic_mirror_sessions(MaxResults=5)
    assert "TrafficMirrorSessions" in resp, f"expected TrafficMirrorSessions key, got {sorted(resp)}"
    assert isinstance(resp["TrafficMirrorSessions"], list), (
        f"expected a list-shaped TrafficMirrorSessions, got {type(resp['TrafficMirrorSessions'])!r}"
    )

    # A session id filter for an id that was never issued matches nothing.
    missing_id = "tms-0123456789abcdef0"
    filtered = ec2.describe_traffic_mirror_sessions(
        Filters=[{"Name": "traffic-mirror-session-id", "Values": [missing_id]}]
    )
    assert filtered["TrafficMirrorSessions"] == [], (
        f"expected no sessions for {missing_id!r}, got {filtered['TrafficMirrorSessions']!r}"
    )

    # Naming the same id directly is a not-found refusal, not an empty list.
    try:
        result = ec2.describe_traffic_mirror_sessions(TrafficMirrorSessionIds=[missing_id])
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == "InvalidTrafficMirrorSessionId.NotFound", (
            f"expected InvalidTrafficMirrorSessionId.NotFound, got {err.get('Code')!r}"
        )
        assert err.get("Message") == f"{missing_id} does not exist", (
            f"unexpected InvalidTrafficMirrorSessionId.NotFound message {err.get('Message')!r}"
        )
    else:
        raise AssertionError(f"expected a not-found refusal for {missing_id!r}, got {result!r}")

    # DescribeTrafficMirrorSessions does not validate filter names: an unrecognized one is accepted and
    # matches nothing.
    resp2 = ec2.describe_traffic_mirror_sessions(
        Filters=[{"Name": "not-a-real-filter", "Values": ["x"]}]
    )
    assert "TrafficMirrorSessions" in resp2, f"expected TrafficMirrorSessions key, got {sorted(resp2)}"
    assert isinstance(resp2["TrafficMirrorSessions"], list), (
        f"expected a list-shaped TrafficMirrorSessions, got {type(resp2['TrafficMirrorSessions'])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
