"""route-server-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "route-server-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']

# Well-formed but never-issued resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "subnet": "subnet-0123456789abcdef0",
    "route_server": "rs-0123456789abcdef0",
    "route_server_endpoint": "rse-0123456789abcdef0",
}


def _probe_errors(probes):
    """Assert a batch of operations all fail with an expected error code.

    *probes* is a list of ``(operation, call, acceptable_codes)``. Every
    mismatch is collected rather than raising on the first one, so a single run
    reports the real code for every probe. A ``ParamValidationError``
    is deliberately left uncaught: it means the request never left the SDK, so the
    probe measured botocore's local validation rather than the service, and that
    is a harness/artifact defect worth a loud crash, not a graded outcome.
    """
    problems: list[str] = []
    for method, call, expected in probes:
        try:
            call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{method}: expected {sorted(expected)}, got {code}")
        else:
            problems.append(f"{method}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRouteServerEndpoint and CreateRouteServerPeer naming unknown route server / endpoint ids
    each fail with one of their listed NotFound or InvalidParameterValue codes."""
    ec2 = ctx.client("ec2")

    a = _ABSENT
    problems = _probe_errors([
        (
            "create_route_server_endpoint",
            lambda: ec2.create_route_server_endpoint(
                RouteServerId=a["route_server"],
                SubnetId=a["subnet"],
            ),
            (
                "InvalidRouteServerId.NotFound",
                "InvalidRouteServerID.NotFound",
                "InvalidParameterValue",
                "InvalidSubnetID.NotFound",
            ),
        ),
        (
            "create_route_server_peer",
            lambda: ec2.create_route_server_peer(
                RouteServerEndpointId=a["route_server_endpoint"],
                PeerAddress="10.0.0.10",
                BgpOptions={"PeerAsn": 65002},
            ),
            (
                "InvalidRouteServerEndpointId.NotFound",
                "InvalidRouteServerEndpointID.NotFound",
                "InvalidParameterValue",
            ),
        ),
    ])
    assert not problems, "unexpected route-server semantics:\n" + "\n".join(problems)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
