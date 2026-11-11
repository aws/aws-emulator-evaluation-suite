"""get-dictionary-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-dictionary-not-found"
GROUP = "errors"
SERVICES = ["elementalinference"]


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDictionary on a syntactically valid but nonexistent id returns ResourceNotFoundException,
    while an identically-shaped call against a real dictionary this check creates succeeds — the
    positive control that separates "rejects a nonexistent id" from "rejects every GetDictionary"."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-dict-")
    real_id = ei.create_dictionary(
        name=name, language="eng", entries='[{"content": "touchdown"}]'
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_dictionary(id=real_id))

    control = ei.get_dictionary(id=real_id)
    assert control["id"] == real_id, f"positive control: expected id {real_id}, got {control.get('id')}"

    bogus_id = "doesnotexist000001"  # 19 chars, matches ^[a-zA-Z0-9]+$ and length<=19
    code, message = _error_code(lambda: ei.get_dictionary(id=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Resource not found", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
