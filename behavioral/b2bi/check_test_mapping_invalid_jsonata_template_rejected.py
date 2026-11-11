"""test-mapping-invalid-jsonata-template-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-mapping-invalid-jsonata-template-rejected"
GROUP = "overly-permissive"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestMapping rejects a syntactically invalid JSONata template with ValidationException and no
    mappedFileContent; the identical call with a valid template succeeds."""
    b2bi = ctx.client("b2bi")
    input_content = json.dumps({"orderId": "PO-77", "amount": 10})

    broken_template = "$foo(("  # unbalanced parens: not a parseable JSONata expression
    error_code = message = None
    try:
        resp = b2bi.test_mapping(
            fileFormat="JSON",
            inputFileContent=input_content,
            mappingTemplate=broken_template,
        )
    except ClientError as err:
        error_code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        resp = None

    assert error_code == "ValidationException", (
        f"expected ValidationException for a syntactically invalid JSONata template, got {error_code}; "
        f"response={resp!r}"
    )
    expected = (
        'JSONata error. Failed to map input file: Expected ")" before end of expression. '
        "From line 1 column 2 to line 1 column 7."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a valid template against the same input succeeds.
    good_resp = b2bi.test_mapping(
        fileFormat="JSON",
        inputFileContent=input_content,
        mappingTemplate="$",
    )
    mapped = json.loads(good_resp["mappedFileContent"])
    if isinstance(mapped, str):
        # mappedFileContent comes back JSON-string-encoded: parsing once yields the JSON text.
        mapped = json.loads(mapped)
    expected = json.loads(input_content)
    assert mapped == expected, (
        f"positive control: valid template '$' must echo the input unchanged, "
        f"expected {expected!r}, got {mapped!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
