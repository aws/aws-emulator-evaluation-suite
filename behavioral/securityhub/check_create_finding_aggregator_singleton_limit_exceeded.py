"""create-finding-aggregator-singleton-limit-exceeded."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-finding-aggregator-singleton-limit-exceeded"
GROUP = "overly-permissive"
SERVICES = ["securityhub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """A second CreateFindingAggregator in the same account/region is rejected with
    InvalidInputException while the singleton exists, and the identical call succeeds once the
    singleton is removed — proving the block is the pre-existing aggregator, not the input."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(ctx, sh)

    _clear_and_restore_aggregator(ctx, sh)

    live_arn = [sh.create_finding_aggregator(RegionLinkingMode="ALL_REGIONS")["FindingAggregatorArn"]]
    ctx.on_cleanup(lambda: _delete_aggregator_if_present(sh, live_arn[0]))

    code, message = _error_code(lambda: sh.create_finding_aggregator(RegionLinkingMode="ALL_REGIONS"))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    account = live_arn[0].split(":")[4]
    expected = (
        f"A finding aggregator already exists for the account ID: {account}. "
        "Delete the aggregator before creating a new one."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: still exactly one aggregator, and it's the original.
    still = sh.list_finding_aggregators()["FindingAggregators"]
    assert len(still) == 1 and still[0]["FindingAggregatorArn"] == live_arn[0], (
        f"expected only the original aggregator {live_arn[0]!r}, got {still!r}"
    )

    # Positive control: the original aggregator is readable and functional.
    got = sh.get_finding_aggregator(FindingAggregatorArn=live_arn[0])
    assert got["RegionLinkingMode"] == "ALL_REGIONS", (
        f"expected ALL_REGIONS, got {got.get('RegionLinkingMode')!r}"
    )

    # Restore: remove the singleton and prove the delete is real (independent read gone, a
    # further mutation on the dead id also fails) before proving the block lifts.
    deleted_arn = live_arn[0]
    sh.delete_finding_aggregator(FindingAggregatorArn=deleted_arn)

    after_delete = sh.list_finding_aggregators().get("FindingAggregators", [])
    assert after_delete == [], f"expected no aggregators after delete, got {after_delete!r}"

    get_code, get_message = _error_code(lambda: sh.get_finding_aggregator(FindingAggregatorArn=deleted_arn))
    assert get_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {get_code}"
    expected = (
        f"A finding aggregator with the provided FindingAggregatorArn: {deleted_arn} does not exist."
    )
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"

    redelete_code, redelete_message = _error_code(
        lambda: sh.delete_finding_aggregator(FindingAggregatorArn=deleted_arn)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {redelete_code}"
    )
    assert redelete_message == expected, f"expected message {expected!r}, got {redelete_message!r}"

    # Identical call now succeeds: the block was the pre-existing singleton, not the input.
    live_arn[0] = sh.create_finding_aggregator(RegionLinkingMode="ALL_REGIONS")["FindingAggregatorArn"]
    restored = sh.list_finding_aggregators()["FindingAggregators"]
    assert len(restored) == 1 and restored[0]["FindingAggregatorArn"] == live_arn[0], (
        f"expected only the recreated aggregator {live_arn[0]!r}, got {restored!r}"
    )


def _clear_and_restore_aggregator(ctx, sh):
    """The aggregator is one per account and region. A pre-existing one is snapshotted, deleted
    for the duration of the check, and recreated with its original linking settings by cleanup."""
    for agg in sh.list_finding_aggregators().get("FindingAggregators", []):
        got = sh.get_finding_aggregator(FindingAggregatorArn=agg["FindingAggregatorArn"])
        original = {"RegionLinkingMode": got["RegionLinkingMode"]}
        if got.get("Regions"):
            original["Regions"] = got["Regions"]
        sh.delete_finding_aggregator(FindingAggregatorArn=agg["FindingAggregatorArn"])
        ctx.on_cleanup(lambda original=original: sh.create_finding_aggregator(**original))


def _delete_aggregator_if_present(sh, arn):
    from botocore.exceptions import ClientError

    try:
        sh.delete_finding_aggregator(FindingAggregatorArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ensure_hub_enabled(ctx, sh):
    """Enable Security Hub for this check. When this call is what turned the hub on, cleanup
    turns it back off, so the account's hub subscription ends in the state it started in."""
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise
        return
    ctx.on_cleanup(sh.disable_security_hub)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
