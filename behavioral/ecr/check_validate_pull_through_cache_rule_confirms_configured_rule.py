"""validate-pull-through-cache-rule-confirms-configured-rule."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "validate-pull-through-cache-rule-confirms-configured-rule"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidatePullThroughCacheRule reports isValid=True for a rule pointed at a public
    upstream (no credentials required) that was actually created via
    CreatePullThroughCacheRule."""
    ecr = ctx.client("ecr")
    prefix = _prefix_name(ctx, "vptc")

    ecr.create_pull_through_cache_rule(
        ecrRepositoryPrefix=prefix, upstreamRegistry="quay", upstreamRegistryUrl="quay.io"
    )
    ctx.on_cleanup(lambda: _safe_delete_ptcr(ecr, prefix))

    resp = ecr.validate_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    assert resp["ecrRepositoryPrefix"] == prefix, resp
    assert resp["upstreamRegistryUrl"] == "quay.io", resp
    assert resp["isValid"] is True, resp
    assert not resp.get("failure"), resp


def _prefix_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"sim2real{kind}-").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    return raw[:28] if raw else f"sim2real{kind}"


def _safe_delete_ptcr(ecr, prefix: str) -> None:
    try:
        ecr.delete_pull_through_cache_rule(ecrRepositoryPrefix=prefix)
    except ecr.exceptions.PullThroughCacheRuleNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
