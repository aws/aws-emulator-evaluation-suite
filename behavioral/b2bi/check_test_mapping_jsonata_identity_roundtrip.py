"""test-mapping-jsonata-identity-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-mapping-jsonata-identity-roundtrip"
GROUP = "data-plane"
SERVICES = ["b2bi"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestMapping with the JSONata identity expression "$" returns the input unchanged, and a
    template projecting one field returns only that field."""
    b2bi = ctx.client("b2bi")
    document = {
        "orderId": "PO-10042",
        "amount": 42,
        "lineItems": [{"sku": "WIDGET-A1", "qty": 3}, {"sku": "WIDGET-B2", "qty": 1}],
    }
    input_content = json.dumps(document)

    resp = b2bi.test_mapping(
        fileFormat="JSON",
        inputFileContent=input_content,
        mappingTemplate="$",
    )

    mapped = _load_mapped(resp["mappedFileContent"])
    assert mapped == document, f"identity JSONata mapping must return the input unchanged, got {mapped!r}"

    # Same input, a template that projects one field: a target that ignores mappingTemplate
    # and always echoes inputFileContent back would pass the identity assertion above but
    # fails this one, since the projected shape differs from the identity's.
    resp2 = b2bi.test_mapping(
        fileFormat="JSON",
        inputFileContent=input_content,
        mappingTemplate="orderId",
    )
    mapped2 = _load_mapped(resp2["mappedFileContent"])
    assert mapped2 == document["orderId"], (
        f"projecting orderId via JSONata must return just that field, got {mapped2!r}"
    )


def _load_mapped(content: str):
    """Parse mappedFileContent, a second time when it comes back JSON-string-encoded."""
    parsed = json.loads(content)
    if isinstance(parsed, str):
        parsed = json.loads(parsed)
    return parsed


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
