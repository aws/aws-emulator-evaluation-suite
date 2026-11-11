"""rule-groups-namespace-list-name-filter."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "rule-groups-namespace-list-name-filter"
GROUP = "list"
SERVICES = ["amp"]

_RULES_YAML = b"""groups:
  - name: sim2real-filter-rules
    rules:
      - record: sim2real:filter
        expr: sum(up)
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRuleGroupsNamespaces with a `name` prefix filter returns only namespaces matching
    that prefix, not sibling namespaces in the same workspace."""
    amp = ctx.client("amp")
    workspace_id = amp.create_workspace(
        alias=ctx.unique_name("sim2real-amp-ws-"), tags={"sim2real:managed": "true"}
    )["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    matching_prefix = ctx.unique_name("sim2real-match-")
    matching_name = f"{matching_prefix}-a"
    other_name = ctx.unique_name("sim2real-other-")

    for nm in (matching_name, other_name):
        amp.create_rule_groups_namespace(
            workspaceId=workspace_id, name=nm, data=_RULES_YAML, tags={"sim2real:managed": "true"}
        )
        _poll_until(
            lambda nm=nm: amp.describe_rule_groups_namespace(workspaceId=workspace_id, name=nm)["ruleGroupsNamespace"]["status"]["statusCode"],
            lambda s: s == "ACTIVE",
            timeout_s=120,
        )

    listed = amp.list_rule_groups_namespaces(workspaceId=workspace_id, name=matching_prefix)["ruleGroupsNamespaces"]
    names = {ns["name"] for ns in listed}
    assert matching_name in names, f"expected {matching_name} in filtered results {names}"
    assert other_name not in names, f"unfiltered {other_name} leaked into name-filtered results {names}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
