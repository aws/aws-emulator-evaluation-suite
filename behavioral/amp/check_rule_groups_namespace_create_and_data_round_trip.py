"""rule-groups-namespace-create-and-data-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "rule-groups-namespace-create-and-data-round-trip"
GROUP = "data-plane"
SERVICES = ["amp"]

_RULES_YAML = b"""groups:
  - name: sim2real-test-rules
    rules:
      - record: sim2real:up:sum
        expr: sum(up)
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRuleGroupsNamespace stores the exact rules YAML blob and it round-trips through
    DescribeRuleGroupsNamespace once the namespace reaches ACTIVE."""
    amp = ctx.client("amp")
    workspace_id = amp.create_workspace(
        alias=ctx.unique_name("sim2real-amp-ws-"), tags={"sim2real-owner": "behavioral"}
    )["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    name = ctx.unique_name("sim2real-rgns-")
    created = amp.create_rule_groups_namespace(
        workspaceId=workspace_id, name=name, data=_RULES_YAML, tags={"sim2real-owner": "behavioral"}
    )
    assert created["name"] == name, f"CreateRuleGroupsNamespace echoed name {created['name']!r}, expected {name!r}"

    status = _poll_until(
        lambda: amp.describe_rule_groups_namespace(workspaceId=workspace_id, name=name)["ruleGroupsNamespace"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "CREATION_FAILED"),
        timeout_s=120,
    )
    assert status == "ACTIVE", f"rule groups namespace reached status {status!r} after creation, expected ACTIVE"

    described = amp.describe_rule_groups_namespace(workspaceId=workspace_id, name=name)["ruleGroupsNamespace"]
    stored = described["data"]
    if isinstance(stored, str):
        stored = stored.encode("utf-8")
    assert bytes(stored) == _RULES_YAML, (
        f"DescribeRuleGroupsNamespace returned {stored!r}, expected the created data {_RULES_YAML!r} to round-trip exactly"
    )


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
