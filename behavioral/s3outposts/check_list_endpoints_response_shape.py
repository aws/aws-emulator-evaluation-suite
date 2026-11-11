"""list-endpoints-response-shape."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-endpoints-response-shape"
GROUP = "control-plane"
SERVICES = ["s3outposts"]

_VALID_STATUSES = {"Pending", "Available", "Deleting", "Create_Failed", "Delete_Failed"}
_VALID_ACCESS_TYPES = {"Private", "CustomerOwnedIp"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEndpoints returns a well-typed Endpoints list; any entries present carry a valid
    ARN and a Status drawn from the documented EndpointStatus enum."""
    s3o = ctx.client("s3outposts")
    resp = s3o.list_endpoints(MaxResults=100)
    assert "Endpoints" in resp, f"ListEndpoints response missing 'Endpoints' key: keys={sorted(resp.keys())}"
    endpoints = resp["Endpoints"]
    assert isinstance(endpoints, list), f"expected Endpoints to be a list, got {type(endpoints).__name__}: {endpoints!r}"
    for ep in endpoints:
        assert ep["EndpointArn"].startswith("arn:"), f"expected EndpointArn to start with 'arn:', got {ep.get('EndpointArn')!r}"
        assert ep["Status"] in _VALID_STATUSES, f"expected Status in {sorted(_VALID_STATUSES)}, got {ep.get('Status')!r}"
        if ep.get("AccessType"):
            assert ep["AccessType"] in _VALID_ACCESS_TYPES, f"expected AccessType in {sorted(_VALID_ACCESS_TYPES)}, got {ep['AccessType']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
