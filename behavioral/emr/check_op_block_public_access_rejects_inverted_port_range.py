"""op-block-public-access-rejects-inverted-port-range."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-block-public-access-rejects-inverted-port-range"
GROUP = 'overly-permissive'
SERVICES = ['emr']

def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")

def _poll_until_ranges_match(emr, expected_ranges, timeout_s: float = 30.0, interval_s: float = 2.0):
    """The block-public-access config store is eventually consistent; poll for the write to land."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"][
            "PermittedPublicSecurityGroupRuleRanges"
        ]
        if last == expected_ranges:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"config never converged on {expected_ranges}, last saw {last}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:emr-block-public-access")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: a permitted-public port range whose MinRange exceeds
    MaxRange must be rejected, and the account configuration left untouched."""
    emr = ctx.client("emr")
    original = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    ctx.on_cleanup(lambda: emr.put_block_public_access_configuration(BlockPublicAccessConfiguration=original))

    # Positive control: a valid range is accepted, so a later rejection proves this specific
    # range is invalid rather than that PutBlockPublicAccessConfiguration is broken outright.
    baseline = {
        "BlockPublicSecurityGroupRules": True,
        "PermittedPublicSecurityGroupRuleRanges": [{"MinRange": 22, "MaxRange": 22}],
    }
    emr.put_block_public_access_configuration(BlockPublicAccessConfiguration=baseline)
    confirmed = _poll_until_ranges_match(emr, baseline["PermittedPublicSecurityGroupRuleRanges"])
    assert confirmed == baseline["PermittedPublicSecurityGroupRuleRanges"], (
        f"positive control: expected {baseline['PermittedPublicSecurityGroupRuleRanges']}, got {confirmed}"
    )

    code, message = _error(
        lambda: emr.put_block_public_access_configuration(
            BlockPublicAccessConfiguration={
                "BlockPublicSecurityGroupRules": True,
                "PermittedPublicSecurityGroupRuleRanges": [{"MinRange": 90, "MaxRange": 20}],
            }
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected_message = (
        "The specified port range (90, 20) is not valid. "
        "Min Range must be less than or equal to Max Range."
    )
    assert message == expected_message, f"unexpected rejection message: {message!r}"

    after = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    assert after.get("PermittedPublicSecurityGroupRuleRanges") == baseline.get(
        "PermittedPublicSecurityGroupRuleRanges"
    ), "a rejected PutBlockPublicAccessConfiguration must not mutate account state"
    assert after.get("BlockPublicSecurityGroupRules") == baseline.get(
        "BlockPublicSecurityGroupRules"
    ), "a rejected PutBlockPublicAccessConfiguration must not mutate account state"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
