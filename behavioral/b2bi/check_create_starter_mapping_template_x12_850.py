"""create-starter-mapping-template-x12-850."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "create-starter-mapping-template-x12-850"
GROUP = "data-plane"
SERVICES = ["b2bi"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateStarterMappingTemplate returns a JSON skeleton of each requested X12 transaction set's
    own segment layout (850 and 855 differ in their segment names)."""
    b2bi = ctx.client("b2bi")

    template_850 = _fetch_template(b2bi, "X12_850")
    st_850 = _terminal_transaction(template_850)
    assert st_850["ST_01_TransactionSetIdentifierCode"] == "850", (
        f"expected the 850 template's own ST_01 to identify transaction set 850, got {st_850.get('ST_01_TransactionSetIdentifierCode')!r}"
    )
    keys_850 = _all_keys(template_850)
    assert "BEG_01" in keys_850, "expected the 850 (Purchase Order) template to contain the standard BEG (Beginning Segment for Purchase Order) segment"

    template_855 = _fetch_template(b2bi, "X12_855")
    st_855 = _terminal_transaction(template_855)
    assert st_855["ST_01_TransactionSetIdentifierCode"] == "855", (
        f"expected the 855 template's own ST_01 to identify transaction set 855, got {st_855.get('ST_01_TransactionSetIdentifierCode')!r}"
    )
    keys_855 = _all_keys(template_855)
    assert "BAK_01" in keys_855, "expected the 855 (PO Acknowledgment) template to contain the standard BAK (Beginning Segment for PO Acknowledgment) segment"

    assert "BAK_01" not in keys_850, "the 850 template must not carry the 855-specific BAK segment -- the layout must track the requested transaction set, not a shared superset"
    assert "BEG_01" not in keys_855, "the 855 template must not carry the 850-specific BEG segment -- the layout must track the requested transaction set, not a shared superset"


def _fetch_template(b2bi: Any, transaction_set: str) -> dict:
    resp = b2bi.create_starter_mapping_template(
        mappingType="JSONATA",
        templateDetails={"x12": {"transactionSet": transaction_set, "version": "VERSION_4010"}},
    )
    raw = resp["mappingTemplate"]
    assert isinstance(raw, str) and len(raw.strip()) > 20, f"expected a substantial starter template for {transaction_set}"
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"starter template for {transaction_set} is not well-formed JSON: {exc}") from exc


def _terminal_transaction(template: dict) -> dict:
    return template["interchanges"][0]["functional_groups"][0]["transactions"][0]


def _all_keys(node: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(node, dict):
        for k, v in node.items():
            keys.add(k)
            keys |= _all_keys(v)
    elif isinstance(node, list):
        for item in node:
            keys |= _all_keys(item)
    return keys


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
