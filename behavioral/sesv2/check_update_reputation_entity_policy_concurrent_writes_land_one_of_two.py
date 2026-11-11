"""update-reputation-entity-policy-concurrent-writes-land-one-of-two."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-reputation-entity-policy-concurrent-writes-land-one-of-two"
GROUP = "concurrency"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing two reputation-management policy writes on one entity lands one of the two values.

    Both writers may succeed; any loser must fail ConflictException, at least one write lands, and
    the final policy is one of the raced ARNs. A solo reset to the standard policy then reads back.
    """
    sesv2 = ctx.client("sesv2")
    tenant_name = ctx.unique_name("sim2real-tenant-")
    tenant = sesv2.create_tenant(
        TenantName=tenant_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    tenant_arn = tenant["TenantArn"]
    ctx.on_cleanup(lambda: sesv2.delete_tenant(TenantName=tenant_name))

    standard_arn = f"arn:aws:ses:{ctx.region}:aws:reputation-policy/standard"
    strict_arn = f"arn:aws:ses:{ctx.region}:aws:reputation-policy/strict"
    none_arn = f"arn:aws:ses:{ctx.region}:aws:reputation-policy/none"

    baseline = sesv2.get_reputation_entity(
        ReputationEntityType="RESOURCE", ReputationEntityReference=tenant_arn
    )["ReputationEntity"]
    assert baseline["ReputationManagementPolicy"] == standard_arn, (
        f"expected default policy {standard_arn}, got {baseline['ReputationManagementPolicy']}"
    )

    barrier = threading.Barrier(2)

    def _apply(policy_arn: str) -> tuple[str, str | None]:
        barrier.wait(timeout=10)
        try:
            sesv2.update_reputation_entity_policy(
                ReputationEntityType="RESOURCE",
                ReputationEntityReference=tenant_arn,
                ReputationEntityPolicy=policy_arn,
            )
            return ("ok", None)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(_apply, [strict_arn, none_arn]))

    outcomes = [r[0] for r in results]
    errors = [r[1] for r in results if r[0] == "error"]
    # A losing writer must fail with the documented ConflictException; AWS may also serialize
    # both writes. Either way at least one write lands and the final policy is one of the raced values.
    for code in errors:
        assert code == "ConflictException", f"loser raised {code}, not ConflictException (results={results})"
    assert outcomes.count("ok") >= 1, f"expected at least one winner, got {results}"

    final = sesv2.get_reputation_entity(
        ReputationEntityType="RESOURCE", ReputationEntityReference=tenant_arn
    )["ReputationEntity"]["ReputationManagementPolicy"]
    assert final in (strict_arn, none_arn), (
        f"final policy {final} is neither raced value ({strict_arn}, {none_arn}) -- corrupted"
    )

    # positive control: a solo update (no contention) succeeds cleanly
    sesv2.update_reputation_entity_policy(
        ReputationEntityType="RESOURCE",
        ReputationEntityReference=tenant_arn,
        ReputationEntityPolicy=standard_arn,
    )
    reset = sesv2.get_reputation_entity(
        ReputationEntityType="RESOURCE", ReputationEntityReference=tenant_arn
    )["ReputationEntity"]["ReputationManagementPolicy"]
    assert reset == standard_arn, f"solo update expected {standard_arn}, got {reset}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
