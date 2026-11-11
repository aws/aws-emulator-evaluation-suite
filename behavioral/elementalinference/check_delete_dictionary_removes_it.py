"""delete-dictionary-removes-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-dictionary-removes-it"
GROUP = "state"
SERVICES = ["elementalinference"]


def _error_code(fn, within_s=0.0, interval_s=2.0):
    """Call fn() until it raises a ClientError and return its (code, message). A call that still
    SUCCEEDS once within_s has passed raises."""
    deadline = time.monotonic() + within_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


def _cleanup_delete(ei, dict_id):
    try:
        ei.delete_dictionary(id=dict_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDictionary transitions the dictionary through DELETING to DELETED and it disappears from GetDictionary; a mutation against the dead id is rejected too."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-dict-")
    dict_id = ei.create_dictionary(name=name, language="eng", entries='[{"content": "offside"}]')["id"]
    ctx.on_cleanup(lambda: _cleanup_delete(ei, dict_id))

    resp = ei.delete_dictionary(id=dict_id)
    assert resp["id"] == dict_id

    code, message = _error_code(lambda: ei.get_dictionary(id=dict_id), within_s=90.0)
    assert code == "ResourceNotFoundException", f"dictionary {dict_id} was not fully removed; code={code}"
    assert message == "Resource not found", message

    mutate_code, mutate_message = _error_code(
        lambda: ei.update_dictionary(id=dict_id, name=ctx.unique_name("sim2real-ei-dict-renamed-"))
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected a mutation against the deleted dictionary to be rejected, got {mutate_code}"
    )
    assert mutate_message == "Resource not found", mutate_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
