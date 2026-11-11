"""model-card-archived-update-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-card-archived-update-rejected"
GROUP = "representation"
SERVICES = ["sagemaker"]

_CONTENT = json.dumps({"model_overview": {"model_description": "sim2real archived-transition check"}})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateModelCard on a missing card is refused with ResourceNotFound (exact message) and creates nothing; a real
    card moves Draft -> PendingReview -> Approved -> Archived, after which UpdateModelCard is refused with
    ValidationException (exact message) and the card stays Archived.
    """
    sm = ctx.client("sagemaker")

    # --- negative: updating a model card that was never created is rejected ---
    missing_name = ctx.unique_name("sim2real-mc-missing-")
    missing_message = (
        f"Modelcard arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-card/{missing_name} "
        "does not exist"
    )
    code, message = _error(lambda: sm.update_model_card(ModelCardName=missing_name, ModelCardStatus="Draft"))
    assert code == "ResourceNotFound", f"expected ResourceNotFound updating a nonexistent model card, got {code!r}"
    expected_message = missing_message
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no card was created as a side effect of the rejected update.
    describe_code, describe_message = _error(lambda: sm.describe_model_card(ModelCardName=missing_name))
    assert describe_code == "ResourceNotFound", (
        f"a model card should not exist after a rejected update, got describe code {describe_code!r}"
    )
    expected_message = missing_message
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )

    # --- positive control: the full lifecycle transitions succeed on a real card ---
    fresh_name = ctx.unique_name("sim2real-mc-fresh-")
    sm.create_model_card(
        ModelCardName=fresh_name,
        Content=_CONTENT,
        ModelCardStatus="Draft",
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_card(ModelCardName=fresh_name))

    for target_status in ("PendingReview", "Approved", "Archived"):
        sm.update_model_card(ModelCardName=fresh_name, ModelCardStatus=target_status)
        updated = sm.describe_model_card(ModelCardName=fresh_name)
        assert updated["ModelCardStatus"] == target_status, (
            f"expected transition to {target_status!r}, got {updated['ModelCardStatus']!r}"
        )

    # --- the check's own named claim: an update issued against an already-Archived
    # card is rejected, not merely advisory ---
    reject_code, reject_message = _error(lambda: sm.update_model_card(ModelCardName=fresh_name, ModelCardStatus="Draft"))
    assert reject_code == "ValidationException", (
        f"expected updating an Archived model card to be rejected with ValidationException, got {reject_code!r}"
    )
    expected_message = "Model card is in archived state"
    assert reject_message == expected_message, (
        f"expected message {expected_message!r}, got {reject_message!r}"
    )
    still_archived = sm.describe_model_card(ModelCardName=fresh_name)
    assert still_archived["ModelCardStatus"] == "Archived", (
        f"status should remain Archived after a rejected update, got {still_archived['ModelCardStatus']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
