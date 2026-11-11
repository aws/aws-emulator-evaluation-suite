"""start-stop-key-usage-toggles-enabled."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-stop-key-usage-toggles-enabled"
GROUP = "state"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopKeyUsage/StartKeyUsage flip Key.Enabled and stamp the matching
    UsageStopTimestamp/UsageStartTimestamp, visible on a subsequent GetKey.
    StartKeyUsage also clears UsageStopTimestamp."""
    pc = ctx.client("payment-cryptography")
    key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    created = pc.create_key(
        KeyAttributes=key_attributes,
        Exportable=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Key"]
    arn = created["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))
    assert created["Enabled"] is True, f"expected new key Enabled=True, got {created['Enabled']!r}"

    stopped = pc.stop_key_usage(KeyIdentifier=arn)["Key"]
    assert stopped["Enabled"] is False, (
        f"expected StopKeyUsage to disable the key, got Enabled={stopped['Enabled']!r}"
    )
    assert "UsageStopTimestamp" in stopped, "StopKeyUsage response missing UsageStopTimestamp"
    refetched = pc.get_key(KeyIdentifier=arn)["Key"]
    assert refetched["Enabled"] is False, (
        f"expected independent GetKey to see Enabled=False after StopKeyUsage, "
        f"got {refetched['Enabled']!r}"
    )
    assert refetched.get("UsageStopTimestamp") == stopped["UsageStopTimestamp"], (
        f"expected independent GetKey's UsageStopTimestamp to match StopKeyUsage's own "
        f"{stopped['UsageStopTimestamp']!r}, got {refetched.get('UsageStopTimestamp')!r}"
    )

    started = pc.start_key_usage(KeyIdentifier=arn)["Key"]
    assert started["Enabled"] is True, (
        f"expected StartKeyUsage to re-enable the key, got Enabled={started['Enabled']!r}"
    )
    assert "UsageStartTimestamp" in started, "StartKeyUsage response missing UsageStartTimestamp"
    assert "UsageStopTimestamp" not in started, (
        f"expected StartKeyUsage to clear UsageStopTimestamp, still present: "
        f"{started.get('UsageStopTimestamp')!r}"
    )
    refetched2 = pc.get_key(KeyIdentifier=arn)["Key"]
    assert refetched2["Enabled"] is True, (
        f"expected independent GetKey to see Enabled=True after StartKeyUsage, "
        f"got {refetched2['Enabled']!r}"
    )
    assert refetched2.get("UsageStartTimestamp") == started["UsageStartTimestamp"], (
        f"expected independent GetKey's UsageStartTimestamp to match StartKeyUsage's own "
        f"{started['UsageStartTimestamp']!r}, got {refetched2.get('UsageStartTimestamp')!r}"
    )
    assert "UsageStopTimestamp" not in refetched2, (
        f"expected independent GetKey to also see UsageStopTimestamp cleared, still present: "
        f"{refetched2.get('UsageStopTimestamp')!r}"
    )


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
