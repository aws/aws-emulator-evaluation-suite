"""get-endpoint-returns-valid-device-advisor-domain."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "get-endpoint-returns-valid-device-advisor-domain"
GROUP = "control-plane"
SERVICES = ["iotdeviceadvisor"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetEndpoint (account-level) returns a well-formed Device Advisor DNS endpoint."""
    da = ctx.client("iotdeviceadvisor")

    resp = da.get_endpoint()
    endpoint = resp["endpoint"]

    assert 45 <= len(endpoint) <= 75, f"expected endpoint length in [45, 75], got {len(endpoint)}: {endpoint!r}"
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", endpoint), f"expected a hostname, got {endpoint!r}"
    assert ctx.region in endpoint, f"expected region {ctx.region!r} embedded in endpoint, got {endpoint!r}"
    assert "deviceadvisor" in endpoint or "devicegateway" in endpoint, (
        f"expected 'deviceadvisor' or 'devicegateway' in endpoint, got {endpoint!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
