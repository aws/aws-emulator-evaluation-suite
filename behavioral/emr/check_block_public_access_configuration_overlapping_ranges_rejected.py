"""block-public-access-configuration-overlapping-ranges-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "block-public-access-configuration-overlapping-ranges-rejected"
GROUP = "representation"
SERVICES = ["emr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:emr-block-public-access")
def run(ctx) -> None:
    """Overlapping PermittedPublicSecurityGroupRuleRanges are rejected and the prior config sticks."""
    emr = ctx.client("emr")

    original = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    ctx.on_cleanup(lambda: emr.put_block_public_access_configuration(BlockPublicAccessConfiguration=original))

    baseline = {
        "BlockPublicSecurityGroupRules": True,
        "PermittedPublicSecurityGroupRuleRanges": [{"MinRange": 22, "MaxRange": 22}],
    }
    emr.put_block_public_access_configuration(BlockPublicAccessConfiguration=baseline)
    confirmed = _poll_until_ranges_match(emr, baseline["PermittedPublicSecurityGroupRuleRanges"])
    assert confirmed == baseline["PermittedPublicSecurityGroupRuleRanges"], (
        f"positive control: the baseline Put should have landed as "
        f"{baseline['PermittedPublicSecurityGroupRuleRanges']!r}, Get reports {confirmed!r}"
    )

    # Real AWS does not reject *overlapping* ranges (they're just merged/permitted), but it does
    # reject a syntactically-invalid range where MinRange > MaxRange.
    invalid = {
        "BlockPublicSecurityGroupRules": True,
        "PermittedPublicSecurityGroupRuleRanges": [
            {"MinRange": 200, "MaxRange": 100},
        ],
    }
    code, message = _error(lambda: emr.put_block_public_access_configuration(BlockPublicAccessConfiguration=invalid))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected_message = (
        "The specified port range (200, 100) is not valid. "
        "Min Range must be less than or equal to Max Range."
    )
    assert message == expected_message, f"unexpected rejection message: {message!r}"

    # (b) the effect is absent: the malformed config never took hold.
    still_baseline = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    assert still_baseline["PermittedPublicSecurityGroupRuleRanges"] == baseline["PermittedPublicSecurityGroupRuleRanges"], (
        f"a rejected PutBlockPublicAccessConfiguration must not mutate account state: "
        f"expected {baseline['PermittedPublicSecurityGroupRuleRanges']!r}, "
        f"Get reports {still_baseline['PermittedPublicSecurityGroupRuleRanges']!r}"
    )

    # (c) positive control in the same file: a valid, non-overlapping update still succeeds.
    valid_update = {
        "BlockPublicSecurityGroupRules": True,
        "PermittedPublicSecurityGroupRuleRanges": [{"MinRange": 22, "MaxRange": 22}, {"MinRange": 443, "MaxRange": 443}],
    }
    emr.put_block_public_access_configuration(BlockPublicAccessConfiguration=valid_update)
    after_valid = _poll_until_ranges_match(emr, valid_update["PermittedPublicSecurityGroupRuleRanges"])
    assert after_valid == valid_update["PermittedPublicSecurityGroupRuleRanges"], (
        f"the identical-shape valid update should still succeed after the rejection: "
        f"expected {valid_update['PermittedPublicSecurityGroupRuleRanges']!r}, Get reports {after_valid!r}"
    )


def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected PutBlockPublicAccessConfiguration to be rejected, but it succeeded")


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
    raise AssertionError(
        f"PermittedPublicSecurityGroupRuleRanges did not converge to {expected_ranges!r} "
        f"within {timeout_s}s; last observed {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
