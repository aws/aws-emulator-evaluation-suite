"""evaluate-mapping-template-util-functions."""
from __future__ import annotations

import json
import re

from behavioral_harness import tags

CHECK = "evaluate-mapping-template-util-functions"
GROUP = "data-plane"
SERVICES = ["appsync"]

_TEMPLATE = (
    '#set($result = {})\n'
    '#set($discard1 = $result.put("echo", $context.arguments.name))\n'
    '#set($discard2 = $result.put("upper", $context.arguments.name.toUpperCase()))\n'
    '#set($discard3 = $result.put("id", $util.autoId()))\n'
    '$util.toJson($result)'
)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """EvaluateMappingTemplate executes VTL: .toUpperCase() and $util.autoId give computed values, and
    two evaluations mint two different autoIds."""
    appsync = ctx.client("appsync")

    def _evaluate(name):
        context = json.dumps({"arguments": {"name": name}, "stash": {}, "result": None})
        resp = appsync.evaluate_mapping_template(template=_TEMPLATE, context=context)
        assert not resp.get("error"), f"unexpected evaluation error: {resp.get('error')}"
        return json.loads(resp["evaluationResult"])

    first = _evaluate("world")
    assert first["echo"] == "world", first
    assert first["upper"] == "WORLD", first
    assert _UUID_RE.match(first["id"]), f"autoId not uuid-shaped: {first['id']}"

    second = _evaluate("second")
    assert second["echo"] == "second", second
    assert second["upper"] == "SECOND", second
    assert _UUID_RE.match(second["id"]), f"autoId not uuid-shaped: {second['id']}"
    assert second["id"] != first["id"], (
        f"util.autoId() returned the same id across two independent evaluations: {first['id']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
