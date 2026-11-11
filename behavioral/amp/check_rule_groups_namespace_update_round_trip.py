"""rule-groups-namespace-update-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "rule-groups-namespace-update-round-trip"
GROUP = "state"
SERVICES = ["amp"]

_RULES_V1 = b"""groups:
  - name: sim2real-v1
    rules:
      - record: sim2real:v1
        expr: sum(up)
"""
_RULES_V2 = b"""groups:
  - name: sim2real-v2
    rules:
      - record: sim2real:v2
        expr: avg(up)
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRuleGroupsNamespace transitions ACTIVE -> UPDATING -> ACTIVE and the stored data and
    modifiedAt both reflect the update."""
    amp = ctx.client("amp")
    workspace_id = amp.create_workspace(
        alias=ctx.unique_name("sim2real-amp-ws-"), tags={"sim2real": "true"}
    )["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    name = ctx.unique_name("sim2real-rgns-")
    amp.create_rule_groups_namespace(
        workspaceId=workspace_id, name=name, data=_RULES_V1, tags={"sim2real": "true"}
    )
    _poll_until(
        lambda: amp.describe_rule_groups_namespace(workspaceId=workspace_id, name=name)["ruleGroupsNamespace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    before = amp.describe_rule_groups_namespace(workspaceId=workspace_id, name=name)["ruleGroupsNamespace"]
    modified_before = before["modifiedAt"]

    amp.put_rule_groups_namespace(workspaceId=workspace_id, name=name, data=_RULES_V2)
    status = _poll_until(
        lambda: amp.describe_rule_groups_namespace(workspaceId=workspace_id, name=name)["ruleGroupsNamespace"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=120,
    )
    assert status == "ACTIVE", f"expected ACTIVE after update, got {status!r}"

    after = amp.describe_rule_groups_namespace(workspaceId=workspace_id, name=name)["ruleGroupsNamespace"]
    stored = after["data"]
    if isinstance(stored, str):
        stored = stored.encode("utf-8")
    assert bytes(stored) == _RULES_V2, f"expected stored data {_RULES_V2!r}, got {bytes(stored)!r}"
    assert after["modifiedAt"] > modified_before, (
        f"modifiedAt must advance after PutRuleGroupsNamespace: before={modified_before!r} "
        f"after={after['modifiedAt']!r}"
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
