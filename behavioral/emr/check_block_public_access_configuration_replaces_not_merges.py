"""block-public-access-configuration-replaces-not-merges."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "block-public-access-configuration-replaces-not-merges"
GROUP = 'policies'
SERVICES = ['emr']

# ACCOUNT-GLOBAL RESOURCE: there is exactly ONE block-public-access configuration
# per account per region, so this check mutates shared account state. It captures
# the incoming configuration before touching anything and registers the restore as
# its first cleanup. It creates no billable resource of any kind.

# Deliberately exotic port ranges: high, unused, and — critically — NOT 22, which
# is in the AWS default exception list. A merging implementation therefore shows up
# as a leftover 22-22 range that replacement semantics forbid.
FIRST_RANGES = [{"MinRange": 9000, "MaxRange": 9010}]
SECOND_RANGES = [{"MinRange": 9100, "MaxRange": 9100}]


def _swallow(fn):
    """Run fn(), swallowing any exception. Teardown-only — never an assertion."""
    fn()


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _ranges(config):
    """The permitted ranges as a comparable SET of (min, max) pairs; an omitted (optional)
    MaxRange is normalised to MinRange, a single-port range."""
    out = set()
    for entry in config.get("PermittedPublicSecurityGroupRuleRanges", []) or []:
        out.add((entry["MinRange"], entry.get("MaxRange", entry["MinRange"])))
    return out


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:emr-block-public-access")
def run(ctx) -> None:
    """PutBlockPublicAccessConfiguration replaces the permitted-port list (set equality after each of
    two Puts), round-trips the block flag both ways, and returns metadata whose CreationDateTime
    does not go backwards and whose CreatedByArn names the calling account and stays stable.
    """
    emr = ctx.client("emr")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    # Capture the incoming account-global configuration and register the restore
    # BEFORE the first mutation.
    incoming = emr.get_block_public_access_configuration()["BlockPublicAccessConfiguration"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: emr.put_block_public_access_configuration(
                BlockPublicAccessConfiguration=incoming
            )
        )
    )

    def _get():
        return emr.get_block_public_access_configuration()

    def _put(ranges, *, block):
        emr.put_block_public_access_configuration(
            BlockPublicAccessConfiguration={
                "BlockPublicSecurityGroupRules": block,
                "PermittedPublicSecurityGroupRuleRanges": ranges,
            }
        )

    expected_first = {(9000, 9010)}
    _put(FIRST_RANGES, block=True)
    # An account-global setting behind a read model: poll Get rather than trust one immediate read.
    first = _poll(
        _get,
        lambda r: _ranges(r["BlockPublicAccessConfiguration"]) == expected_first,
        timeout_s=120,
        interval_s=5,
        description="the first Put becomes visible to Get",
    )
    first_config = first["BlockPublicAccessConfiguration"]
    assert _ranges(first_config) == expected_first, (
        f"PutBlockPublicAccessConfiguration must REPLACE the permitted-port list, "
        f"not merge into it: submitted {expected_first!r}, Get reports "
        f"{_ranges(first_config)!r} (the extra entries are the account's previous "
        f"configuration surviving a replacement)"
    )
    assert first_config["BlockPublicSecurityGroupRules"] is True, (
        f"BlockPublicSecurityGroupRules must round-trip as True, got "
        f"{first_config['BlockPublicSecurityGroupRules']!r}"
    )

    first_meta = first["BlockPublicAccessConfigurationMetadata"]
    assert first_meta.get("CreationDateTime") is not None, (
        f"GetBlockPublicAccessConfiguration must return the REQUIRED metadata "
        f"CreationDateTime, got {first_meta!r}"
    )
    created_by = first_meta.get("CreatedByArn", "")
    assert created_by.startswith("arn:"), (
        f"CreatedByArn must be a well-formed ARN, got {created_by!r}"
    )
    assert account in created_by, (
        f"CreatedByArn must name the calling account {account}, got {created_by!r}"
    )

    # Second Put: this is the assertion an append-only implementation fails, and it
    # does not depend on the account's starting state at all — 9000-9010 was put
    # there by this check.
    expected_second = {(9100, 9100)}
    _put(SECOND_RANGES, block=False)
    second = _poll(
        _get,
        lambda r: _ranges(r["BlockPublicAccessConfiguration"]) == expected_second,
        timeout_s=120,
        interval_s=5,
        description="the second Put becomes visible to Get",
    )
    second_config = second["BlockPublicAccessConfiguration"]
    assert _ranges(second_config) == expected_second, (
        f"the second Put must fully replace the list this check itself installed: "
        f"submitted {expected_second!r}, Get reports {_ranges(second_config)!r} — "
        f"9000-9010 survived, so the implementation appends rather than replaces"
    )
    assert second_config["BlockPublicSecurityGroupRules"] is False, (
        f"BlockPublicSecurityGroupRules must round-trip as False too, got "
        f"{second_config['BlockPublicSecurityGroupRules']!r}"
    )

    second_meta = second["BlockPublicAccessConfigurationMetadata"]
    assert second_meta.get("CreationDateTime") is not None, (
        f"the metadata must survive a second Put, got {second_meta!r}"
    )
    assert second_meta["CreationDateTime"] >= first_meta["CreationDateTime"], (
        f"each Put must restamp CreationDateTime; it went backwards: "
        f"{first_meta['CreationDateTime']!r} -> {second_meta['CreationDateTime']!r}"
    )
    assert second_meta.get("CreatedByArn") == created_by, (
        f"the same principal made both Puts, so CreatedByArn must be stable: "
        f"{created_by!r} -> {second_meta.get('CreatedByArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
