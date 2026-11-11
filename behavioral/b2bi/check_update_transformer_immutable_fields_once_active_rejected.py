"""update-transformer-immutable-fields-once-active-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-transformer-immutable-fields-once-active-rejected"
GROUP = "overly-permissive"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTransformer changing the mapping template of an active transformer fails with
    ValidationException and leaves it unchanged; the same change while inactive succeeds."""
    b2bi = ctx.client("b2bi")

    transformer_id = _create_transformer(ctx)

    # Positive control: while still Inactive, UpdateTransformer can change the mapping.
    inactive_template = "$merge([{}, {'note': 'updated-while-inactive'}])"
    updated_inactive = b2bi.update_transformer(
        transformerId=transformer_id,
        mapping={"templateLanguage": "JSONATA", "template": inactive_template},
    )
    assert updated_inactive["mapping"]["template"] == inactive_template, (
        f"expected the positive-control update to echo the new template, got {updated_inactive['mapping']['template']!r}"
    )
    got_inactive = b2bi.get_transformer(transformerId=transformer_id)["mapping"]["template"]
    assert got_inactive == inactive_template, (
        f"expected an independent read to reflect the positive-control update, got {got_inactive!r}"
    )

    b2bi.update_transformer(transformerId=transformer_id, status="active")
    activated_status = b2bi.get_transformer(transformerId=transformer_id)["status"]
    assert activated_status == "active", f"expected the transformer to activate, got {activated_status!r}"

    # Once active, even an unrelated field (the mapping template) cannot be modified.
    blocked_template = "$merge([{}, {'note': 'should-not-apply'}])"
    code, message = _error(
        lambda: b2bi.update_transformer(
            transformerId=transformer_id,
            mapping={"templateLanguage": "JSONATA", "template": blocked_template},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "An active Transformer cannot be updated"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_template = b2bi.get_transformer(transformerId=transformer_id)["mapping"]["template"]
    assert still_template == inactive_template, (
        f"a rejected mapping update on an active transformer must leave its mapping unchanged, got {still_template!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_transformer(ctx: Any) -> str:
    b2bi = ctx.client("b2bi")
    resp = b2bi.create_transformer(
        name=ctx.unique_name("sim2real-b2bi-xfmr-"),
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
        tags=[{"Key": "sim2real-created-with", "Value": CHECK}],
    )
    transformer_id = resp["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))
    return transformer_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

