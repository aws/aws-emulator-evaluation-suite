"""describe-registry-reflects-replication-config."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "describe-registry-reflects-replication-config"
GROUP = "server-side"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-replication")
def run(ctx) -> None:
    """PutReplicationConfiguration is durably applied and reflected in subsequent
    DescribeRegistry responses without any separate write — DescribeRegistry serves the
    persisted server-side replication state, not a stale value."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    original = ecr.describe_registry()["replicationConfiguration"]
    ctx.on_cleanup(lambda: ecr.put_replication_configuration(replicationConfiguration=original))

    # Literal, not ctx.region: ECR rejects a same-region replication destination
    # (InvalidParameterException), so the destination must be a second, concrete region
    # distinct from wherever ctx.region happens to land.
    destination_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    filter_pattern = _ecr_name(ctx, "sim2real-repl")

    new_config = {
        "rules": [
            {
                "destinations": [{"region": destination_region, "registryId": account_id}],
                "repositoryFilters": [{"filter": filter_pattern, "filterType": "PREFIX_MATCH"}],
            }
        ]
    }
    put_resp = ecr.put_replication_configuration(replicationConfiguration=new_config)
    put_region = put_resp["replicationConfiguration"]["rules"][0]["destinations"][0]["region"]
    assert put_region == destination_region, f"PutReplicationConfiguration echoed region {put_region!r}, expected {destination_region!r}"

    def _matching_rule(cfg):
        for rule in cfg.get("rules", []):
            if any(f["filter"] == filter_pattern for f in rule["repositoryFilters"]):
                return rule
        return None

    described = _poll_until(
        lambda: ecr.describe_registry()["replicationConfiguration"],
        lambda cfg: _matching_rule(cfg) is not None,
    )
    matching_rule = _matching_rule(described)
    assert matching_rule is not None, f"DescribeRegistry never reflected the new replication rule: {described}"
    got_region = matching_rule["destinations"][0]["region"]
    assert got_region == destination_region, f"DescribeRegistry reflected destination region {got_region!r}, expected {destination_region!r}"
    got_registry_id = matching_rule["destinations"][0]["registryId"]
    assert got_registry_id == account_id, f"DescribeRegistry reflected registryId {got_registry_id!r}, expected {account_id!r}"


def _ecr_name(ctx, base: str, max_len: int = 30) -> str:
    raw = ctx.unique_name(base).lower()
    raw = re.sub(r"[^a-z0-9\-]", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    return raw[:max_len]


def _poll_until(probe, predicate, timeout_s: float = 20.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
