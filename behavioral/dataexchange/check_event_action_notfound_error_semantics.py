"""event-action-notfound-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-action-notfound-error-semantics"
GROUP = "lifecycle"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Get, Update and DeleteEventAction on a never-created EventActionId each fail with ResourceNotFoundException
    "The requested resource was not found.", and ListEventActions succeeds without that id."""
    dx = ctx.client("dataexchange")
    bogus_id = "b" * 38  # well-formed per the Id pattern, never created

    code_get, code_get_message = _error(lambda: dx.get_event_action(EventActionId=bogus_id))
    assert code_get == "ResourceNotFoundException", (
        f"GetEventAction on a never-created id: expected ResourceNotFoundException, got {code_get!r}"
    )
    assert code_get_message == "The requested resource was not found.", f"expected the exact refusal message, got {code_get_message!r}"

    code_update, code_update_message = _error(
        lambda: dx.update_event_action(
            EventActionId=bogus_id,
            Action={"ExportRevisionToS3": {"RevisionDestination": {"Bucket": "sim2real-nonexistent-bucket"}}},
        )
    )
    assert code_update == "ResourceNotFoundException", (
        f"UpdateEventAction on a never-created id: expected ResourceNotFoundException, got {code_update!r}"
    )
    assert code_update_message == "The requested resource was not found.", f"expected the exact refusal message, got {code_update_message!r}"

    code_delete, code_delete_message = _error(lambda: dx.delete_event_action(EventActionId=bogus_id))
    assert code_delete == "ResourceNotFoundException", (
        f"DeleteEventAction on a never-created id: expected ResourceNotFoundException, got {code_delete!r}"
    )
    assert code_delete_message == "The requested resource was not found.", f"expected the exact refusal message, got {code_delete_message!r}"

    # Sanity: ListEventActions always succeeds and returns a list, even with none present.
    listing = dx.list_event_actions()
    assert isinstance(listing["EventActions"], list), (
        f"ListEventActions: expected a list, got {type(listing['EventActions'])!r}"
    )
    assert bogus_id not in {ea["Id"] for ea in listing["EventActions"]}, (
        f"never-created id {bogus_id!r} must not appear in ListEventActions"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

