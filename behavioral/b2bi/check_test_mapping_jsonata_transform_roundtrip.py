"""test-mapping-jsonata-transform-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-mapping-jsonata-transform-roundtrip"
GROUP = "data-plane"
SERVICES = ["b2bi"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestMapping applies a real JSONata expression against the input content, not just echoes it."""
    b2bi = ctx.client("b2bi")

    resp = b2bi.test_mapping(
        fileFormat="JSON",
        inputFileContent=json.dumps({"a": 3, "b": 4}),
        mappingTemplate='{"sum": a + b}',
    )
    mapped = _load_mapped(resp["mappedFileContent"])
    assert mapped == {"sum": 7}, f"expected JSONata sum transform, got {mapped!r}"

    # A second, differently-shaped JSONata expression against different input must produce a
    # differently-shaped result -- proving the engine evaluates the template, not memoized output.
    resp2 = b2bi.test_mapping(
        fileFormat="JSON",
        inputFileContent=json.dumps({"first": "Jane", "last": "Doe"}),
        mappingTemplate='{"fullName": first & " " & last}',
    )
    mapped2 = _load_mapped(resp2["mappedFileContent"])
    assert mapped2 == {"fullName": "Jane Doe"}, f"expected JSONata string concatenation, got {mapped2!r}"


def _load_mapped(content: str):
    """mappedFileContent is the mapped file's raw text; on real AWS it has been observed to
    come back JSON-string-encoded (parsing once yields a str containing the JSON text rather
    than the parsed document), so parse again when that happens."""
    parsed = json.loads(content)
    if isinstance(parsed, str):
        parsed = json.loads(parsed)
    return parsed


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
