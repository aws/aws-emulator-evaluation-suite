"""create-dictionary-invalid-name-validation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-dictionary-invalid-name-validation"
GROUP = "errors"
SERVICES = ["elementalinference"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected CreateDictionary to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDictionary rejects a name that violates the ResourceName pattern with ValidationException,
    creates nothing, and the identical request with a valid name in place of the bad one succeeds (so
    the rejection is about the pattern, not CreateDictionary being broken)."""
    ei = ctx.client("elementalinference")
    base_name = ctx.unique_name("sim2real-ei-dict-")
    bad_name = base_name + " bad!"  # space and '!' violate the pattern

    code, message = _error_code(
        lambda: ei.create_dictionary(name=bad_name, language="eng", entries='[{"content": "test"}]')
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        f"1 validation error detected: Value '{bad_name}' at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9]([a-zA-Z0-9-_]{0,126}[a-zA-Z0-9])?"
    )
    assert message == expected, message

    token = None
    for _ in range(50):
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = ei.list_dictionaries(**kwargs)
        assert all(d["name"] != bad_name for d in page["dictionaries"]), "rejected dictionary was created anyway"
        token = page.get("nextToken")
        if not token:
            break

    # Positive control: the same request with a valid name in place of bad_name succeeds.
    control_id = ei.create_dictionary(
        name=base_name, language="eng", entries='[{"content": "test"}]',
        tags={"Environment": "sim2real-behav", "ManagedBy": "iac"},
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_dictionary(id=control_id))
    control = ei.get_dictionary(id=control_id)
    assert control["name"] == base_name, f"expected name {base_name!r}, got {control['name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
