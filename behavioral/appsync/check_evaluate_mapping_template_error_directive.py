"""evaluate-mapping-template-error-directive."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "evaluate-mapping-template-error-directive"
GROUP = "data-plane"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """$util.error() in a mapping template surfaces in EvaluateMappingTemplate's error.message with the
    per-run message and short-circuits: a later stash write never runs and evaluationResult is empty."""
    appsync = ctx.client("appsync")
    tag = uuid.uuid4().hex
    template = (
        '#set($msg = "boom-$context.arguments.tag")\n'
        '$util.error($msg, "BoomType")\n'
        '$util.qr($context.stash.put("neverReached", true))'
    )
    context = json.dumps({"arguments": {"tag": tag}, "stash": {}, "result": None})

    resp = appsync.evaluate_mapping_template(template=template, context=context)

    error = resp.get("error") or {}
    assert error.get("message") == f"boom-{tag}", f"unexpected error payload: {resp}"
    assert not resp.get("evaluationResult"), (
        f"evaluationResult should be empty when $util.error short-circuits: {resp}"
    )
    stash = json.loads(resp.get("stash") or "{}")
    assert stash == {}, (
        f"a stash write placed after $util.error must never execute -- short-circuit failed: {resp}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
