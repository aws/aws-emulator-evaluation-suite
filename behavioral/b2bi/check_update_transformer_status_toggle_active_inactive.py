"""update-transformer-status-toggle-active-inactive."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-transformer-status-toggle-active-inactive"
GROUP = "state-transition"
SERVICES = ["b2bi"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new transformer is inactive and UpdateTransformer can make it active; flipping an active
    transformer back to inactive fails with ValidationException and leaves its status unchanged."""
    b2bi = ctx.client("b2bi")
    name = ctx.unique_name("sim2real-b2bi-tr-")

    created = b2bi.create_transformer(
        name=name,
        inputConversion={
            "fromFormat": "X12",
            "formatOptions": {"x12": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        },
        mapping={"templateLanguage": "JSONATA", "template": "$"},
        tags=[{"Key": "sim2real-created-with", "Value": "update-transformer-status-toggle-active-inactive"}],
    )
    transformer_id = created["transformerId"]
    ctx.on_cleanup(lambda: b2bi.delete_transformer(transformerId=transformer_id))

    assert created["status"] == "inactive", f"expected a freshly created transformer to be inactive, got {created['status']!r}"
    fetched = b2bi.get_transformer(transformerId=transformer_id)["status"]
    assert fetched == "inactive", f"expected GetTransformer to reflect inactive, got {fetched!r}"

    activated = b2bi.update_transformer(transformerId=transformer_id, status="active")
    assert activated["status"] == "active", f"expected UpdateTransformer's own response to report active, got {activated['status']!r}"
    fetched = b2bi.get_transformer(transformerId=transformer_id)["status"]
    assert fetched == "active", f"expected GetTransformer to reflect active after activation, got {fetched!r}"

    # Once active, the transformer is immutable: UpdateTransformer refuses to flip it back
    # to inactive (there is no documented active -> inactive transition).
    code, message = _error(lambda: b2bi.update_transformer(transformerId=transformer_id, status="inactive"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "An active Transformer cannot be updated"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    still = b2bi.get_transformer(transformerId=transformer_id)["status"]
    assert still == "active", (
        f"a rejected attempt to deactivate must not change the transformer's status, got {still!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
