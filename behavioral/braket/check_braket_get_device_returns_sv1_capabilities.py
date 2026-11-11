"""braket-get-device-returns-sv1-capabilities."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "braket-get-device-returns-sv1-capabilities"
GROUP = "control-plane"
SERVICES = ["braket"]

SV1_ARN = "arn:aws:braket:::device/quantum-simulator/amazon/sv1"


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDevice on the always-available SV1 on-demand simulator returns consistent metadata."""
    braket = ctx.client("braket")
    try:
        device = braket.get_device(deviceArn=SV1_ARN)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            raise AssertionError(
                f"SV1 simulator device ({SV1_ARN}) is not exposed in region {ctx.region}"
            )
        raise
    assert device["deviceArn"] == SV1_ARN, (
        f"expected deviceArn {SV1_ARN!r}, got {device['deviceArn']!r}"
    )
    assert device["deviceType"] == "SIMULATOR", (
        f"expected deviceType 'SIMULATOR', got {device['deviceType']!r}"
    )
    assert device["deviceStatus"] == "ONLINE", (
        f"expected deviceStatus 'ONLINE' for the always-available SV1 simulator, "
        f"got {device['deviceStatus']!r}"
    )
    assert device["providerName"] == "Amazon Braket", (
        f"expected providerName 'Amazon Braket', got {device['providerName']!r}"
    )
    capabilities = json.loads(device["deviceCapabilities"])
    assert isinstance(capabilities, dict), (
        f"expected deviceCapabilities to decode to a JSON object, got {type(capabilities).__name__}"
    )
    assert "action" in capabilities, (
        f"deviceCapabilities JSON is missing the 'action' section; keys were {sorted(capabilities)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
