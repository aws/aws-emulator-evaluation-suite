"""generate-mapping-bedrock-produces-template."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "generate-mapping-bedrock-produces-template"
GROUP = "data-plane"
SERVICES = ["b2bi"]

_SUPPORTED_REGIONS = ("us-east-1", "us-west-2")

_SAMPLE_A = {"orderId": "PO-9001", "customerName": "Acme Corp", "total": 199.99}
_SAMPLE_B = {"orderId": "PO-7777", "customerName": "Globex Inc", "total": 42.5}
_OUTPUT_SHAPE = {"order_reference": "PO-9001", "buyer": "Acme Corp", "amount_due": 199.99}


def _values(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _values(v)
    else:
        yield obj


def _mapped_document(content: str):
    """The mapped JSON document: mappedFileContent is a JSON string literal wrapping it."""
    parsed = json.loads(content)
    return json.loads(parsed) if isinstance(parsed, str) else parsed


def _carries_value(obj, value) -> bool:
    return any(v == value or str(v) == str(value) for v in _values(obj))


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateMapping derives a non-empty JSONata template (mappingAccuracy, when present, in
    [0, 100]) from a sample pair, and TestMapping with that template maps two different inputs to
    two different outputs, each carrying its own input's total."""
    if ctx.region not in _SUPPORTED_REGIONS:
        raise AssertionError(
            "AWS B2BI generative-AI-assisted mapping (GenerateMapping) is documented as "
            f"available only in {_SUPPORTED_REGIONS} on real AWS; "
            f"current region {ctx.region!r} would fail for reasons unrelated to fidelity"
        )

    b2bi = ctx.client("b2bi")

    resp = b2bi.generate_mapping(
        inputFileContent=json.dumps(_SAMPLE_A),
        outputFileContent=json.dumps(_OUTPUT_SHAPE),
        mappingType="JSONATA",
    )

    template = resp["mappingTemplate"]
    assert isinstance(template, str) and len(template.strip()) > 0, "expected a non-empty generated mapping template"

    accuracy = resp.get("mappingAccuracy")
    if accuracy is not None:
        # AWS returns a percentage, not the [0, 1] fraction the model's range on this shape states.
        assert 0.0 <= accuracy <= 100.0, f"mappingAccuracy must be a percentage in [0, 100], got {accuracy!r}"

    mapped_a = _mapped_document(
        b2bi.test_mapping(
            inputFileContent=json.dumps(_SAMPLE_A), mappingTemplate=template, fileFormat="JSON"
        )["mappedFileContent"]
    )
    mapped_b = _mapped_document(
        b2bi.test_mapping(
            inputFileContent=json.dumps(_SAMPLE_B), mappingTemplate=template, fileFormat="JSON"
        )["mappedFileContent"]
    )
    assert mapped_a != mapped_b, (
        "the same generated template applied to two different inputs produced identical "
        f"output ({mapped_a!r}) -- a static stub would do exactly this"
    )
    assert _carries_value(mapped_a, _SAMPLE_A["total"]) and _carries_value(mapped_b, _SAMPLE_B["total"]), (
        "expected each mapped output to carry its own input's 'total' value through the "
        f"generated template; got {mapped_a!r} for input total {_SAMPLE_A['total']!r} and "
        f"{mapped_b!r} for input total {_SAMPLE_B['total']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
