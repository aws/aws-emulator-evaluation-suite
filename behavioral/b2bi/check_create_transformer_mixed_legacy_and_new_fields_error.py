"""create-transformer-mixed-legacy-and-new-fields-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-transformer-mixed-legacy-and-new-fields-error"
GROUP = "error-semantics"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTransformer rejects mixing the deprecated fields (fileFormat, mappingTemplate, ediType)
    with inputConversion with ValidationException and creates nothing, while either style alone
    succeeds."""
    b2bi = ctx.client("b2bi")

    mixed_name = ctx.unique_name("sim2real-b2bi-xfmr-")
    code, message = _error(
        ctx,
        lambda: b2bi.create_transformer(
            name=mixed_name,
            tags=[{"Key": "sim2real-created-with", "Value": "create-transformer-mixed-legacy-and-new-fields-error"}],
            fileFormat="JSON",
            mappingTemplate="$",
            ediType={"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
            inputConversion={
                "fromFormat": "X12",
                "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
            },
        ),
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "A Transformer must use the fields input, mapping, and output, or the fields fileFormat, "
        "mappingTemplate, ediType, and sampleDocument. These fields must not be mixed"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert not _transformer_name_exists(ctx, mixed_name), "the rejected request must not have created a transformer"

    # Positive control 1: the deprecated fields alone succeed and leave the transformer inactive,
    # as inputConversion does.
    legacy_resp = b2bi.create_transformer(
        name=ctx.unique_name("sim2real-b2bi-xfmr-legacy-"),
        tags=[{"Key": "sim2real-created-with", "Value": "create-transformer-mixed-legacy-and-new-fields-error"}],
        fileFormat="JSON",
        mappingTemplate="$",
        ediType={"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
    )
    legacy_id = legacy_resp["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=legacy_id))
    legacy_status = b2bi.get_transformer(transformerId=legacy_id)["status"]
    assert legacy_status == "inactive", f"expected a freshly created transformer to be inactive, got {legacy_status!r}"

    # Positive control 2: new-style fields alone succeed.
    new_resp = b2bi.create_transformer(
        name=ctx.unique_name("sim2real-b2bi-xfmr-new-"),
        tags=[{"Key": "sim2real-created-with", "Value": "create-transformer-mixed-legacy-and-new-fields-error"}],
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
    )
    new_id = new_resp["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=new_id))
    new_status = b2bi.get_transformer(transformerId=new_id)["status"]
    assert new_status == "inactive", f"expected a freshly created transformer to be inactive, got {new_status!r}"


def _error(ctx, fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check. Any resource the call created is
    registered for cleanup before the raise."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    transformer_id = result.get("transformerId")
    if transformer_id:
        b2bi = ctx.client("b2bi")
        ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    raise AssertionError(
        f"expected ValidationException from a request mixing legacy and new-style fields, "
        f"but it succeeded and returned {result!r}"
    )


def _transformer_name_exists(ctx, name: str) -> bool:
    b2bi = ctx.client("b2bi")
    token = None
    while True:
        kwargs = {}
        if token:
            kwargs["nextToken"] = token
        page = b2bi.list_transformers(**kwargs)
        if any(t["name"] == name for t in page.get("transformers", [])):
            return True
        token = page.get("nextToken")
        if not token:
            return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
