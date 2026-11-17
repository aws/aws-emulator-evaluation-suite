"""evaluate-mapping-template-foreach-iteration-limit."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "evaluate-mapping-template-foreach-iteration-limit"
GROUP = "evaluate"
SERVICES = ["appsync"]

_LIMIT = 1000
_CONTEXT = json.dumps({"arguments": {}})


def _template(count: int) -> str:
    return f"#set($n=0)#foreach($i in [1..{count}])#set($n=$velocityCount)#end$util.toJson($n)"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A #foreach range loop of exactly 1,000 iterations renders; one more iteration is refused
    with no usable result, and a loop back at the ceiling renders again."""
    svc = ctx.client("appsync")

    at_limit = svc.evaluate_mapping_template(template=_template(_LIMIT), context=_CONTEXT)
    assert at_limit.get("error") in (None, {}), (
        f"a loop of exactly {_LIMIT} iterations must render, got error {at_limit.get('error')}"
    )
    assert json.loads(at_limit["evaluationResult"]) == _LIMIT, (
        f"expected $n to end at {_LIMIT}, got {at_limit.get('evaluationResult')!r}"
    )

    over_limit = svc.evaluate_mapping_template(template=_template(_LIMIT + 1), context=_CONTEXT)
    error = over_limit.get("error") or {}
    message = error.get("message")
    assert message == "A processing limit has been exceeded", (
        f"expected AWS's exact ceiling-exceeded message past {_LIMIT} iterations, got {message!r} "
        f"(full response: {over_limit!r})"
    )
    assert not over_limit.get("evaluationResult"), (
        f"a loop over the ceiling must not produce a usable evaluationResult: {over_limit!r}"
    )

    restored = svc.evaluate_mapping_template(template=_template(_LIMIT), context=_CONTEXT)
    assert restored.get("error") in (None, {}), (
        f"a loop back down at {_LIMIT} iterations must render again, got error {restored.get('error')}"
    )
    assert json.loads(restored["evaluationResult"]) == _LIMIT, (
        f"expected the restored render's $n to equal {_LIMIT}, got {restored.get('evaluationResult')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
