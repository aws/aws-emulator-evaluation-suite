"""flow-log-fleet-and-gateway-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _probe_errors(client, probes):
    """Assert a batch of operations all fail with an expected error code and message.

    *probes* is a list of ``(client_method, kwargs, expected_code, expected_message)``. Every
    mismatch is collected rather than raising on the first, and operations the
    installed botocore does not know about are reported as skipped. Returns
    ``(problems, skipped)``.
    """
    problems = []
    skipped = []
    for method, kwargs, expected_code, expected_message in probes:
        fn = getattr(client, method, None)
        if fn is None:
            skipped.append(method)
            continue
        try:
            fn(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            if (code, message) != (expected_code, expected_message):
                problems.append(
                    f"{method}: expected {(expected_code, expected_message)!r}, got {(code, message)!r}"
                )
        else:
            problems.append(f"{method}: expected {expected_code} but the call SUCCEEDED")
    return problems, skipped


# Well-formed but nonexistent resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "vpc": "vpc-0123456789abcdef0",
    "flow_log": "fl-0123456789abcdef0",
    "fleet": "fleet-12345678-1234-1234-1234-123456789012",
}

CHECK = "flow-log-fleet-and-gateway-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Flow logs, fleets and carrier gateways: rejection vs. per-item batch reporting."""
    ec2 = ctx.client("ec2")
    a = _ABSENT

    problems, _ = _probe_errors(ec2, [
        (
            "create_flow_logs",
            {
                "ResourceIds": [a["vpc"]],
                "ResourceType": "VPC",
                "TrafficType": "ALL",
                "LogDestinationType": "cloud-watch-logs",
                "LogGroupName": "sim2real-behav-no-such-group",
            },
            # Note the lower-case "Id" here, unlike InvalidVpcID.NotFound elsewhere.
            "InvalidVpcId.NotFound",
            f"Unknown resource {a['vpc']}",
        ),
        (
            "delete_flow_logs",
            {"FlowLogIds": [a["flow_log"]]},
            "InvalidFlowLogId.NotFound",
            f"These flow log ids in the input list are not found: [TotalCount: 1] {a['flow_log']}",
        ),
        (
            "create_carrier_gateway",
            {"VpcId": a["vpc"]},
            "InvalidVpcId.Malformed",
            f"The vpc ID '{a['vpc']}' is malformed",
        ),
    ])
    assert not problems, "unexpected flow-log/gateway error semantics:\n" + "\n".join(problems)

    # DeleteFleets is a BATCH operation: an unknown fleet id is reported per-item
    # in UnsuccessfulFleetDeletions rather than raising. An emulator that raises
    # here (or that reports success) has the wrong batch semantics.
    resp = ec2.delete_fleets(FleetIds=[a["fleet"]], TerminateInstances=True)
    assert resp.get("SuccessfulFleetDeletions", []) == [], (
        f"unknown fleet must not be reported as deleted: {resp}"
    )
    unsuccessful = resp.get("UnsuccessfulFleetDeletions", [])
    assert len(unsuccessful) == 1, f"expected one per-item failure, got {resp}"
    assert unsuccessful[0]["FleetId"] == a["fleet"], (
        f"expected the per-item failure to name {a['fleet']!r}, got {unsuccessful[0]!r}"
    )
    assert unsuccessful[0]["Error"]["Code"] == "fleetIdDoesNotExist", (
        f"unexpected per-item error code: {unsuccessful[0]}"
    )
    assert unsuccessful[0]["Error"]["Message"] == "Fleet deletion failed. Fleet ID not found.", (
        f"unexpected per-item error message: {unsuccessful[0]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
