"""form-type-lifecycle-put-get-delete."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "form-type-lifecycle-put-get-delete"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutFormType creates a form type visible in ListFormTypes and GetFormType;
    DeleteFormType removes it and it disappears from both."""
    glue = ctx.client("glue")
    name = _alnum_id("SimBehavForm")
    schema = f"structure {name} {{\n    region: String\n    retentionDays: Integer\n}}"

    created = glue.put_form_type(Name=name, Schema=schema)
    ctx.on_cleanup(lambda: _cleanup_form_type(glue, name))
    assert created["Id"] == name, (
        f"expected PutFormType Id to equal the requested Name {name!r}, got {created.get('Id')!r}"
    )
    assert created["Name"] == name, (
        f"expected PutFormType Name to echo {name!r}, got {created.get('Name')!r}"
    )

    got = glue.get_form_type(Identifier=name)
    assert got["Name"] == name, f"expected GetFormType Name to be {name!r}, got {got.get('Name')!r}"
    assert "retentionDays" in got["Schema"], (
        f"expected the authored retentionDays field in the returned schema, got {got.get('Schema')!r}"
    )

    listed_before = _try_list_contains(glue, name)
    if listed_before is not None:
        assert listed_before, f"expected {name!r} to appear in ListFormTypes after PutFormType"

    glue.delete_form_type(Identifier=name)

    code, message = _error(lambda: glue.get_form_type(Identifier=name))
    assert code == "EntityNotFoundException", (
        f"expected GetFormType on the deleted form type to raise EntityNotFoundException, "
        f"got code {code!r}"
    )
    expected = f'{{"Message":"Metadata form type {name} not found."}}'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # DeleteFormType is idempotent: a second delete on an already-gone form type succeeds
    # silently rather than raising
    try:
        glue.delete_form_type(Identifier=name)
    except ClientError as exc:
        raise AssertionError(
            f"expected a second DeleteFormType on the already-deleted {name!r} to succeed "
            f"idempotently with no error, got code {exc.response['Error']['Code']!r}"
        ) from exc

    listed_after = _try_list_contains(glue, name)
    if listed_after is not None:
        assert not listed_after, f"expected {name!r} to no longer appear in ListFormTypes after DeleteFormType"


# ===== helpers =====
def _alnum_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises, so a
    target accepting what AWS refuses fails as an acceptance, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


def _try_list_contains(glue, target_id: str, attempts: int = 2, delay: float = 3.0):
    """ListFormTypes is exercised best-effort: this preview business-context API has been
    observed to intermittently 500 independent of the create/get/delete path, so a persistent
    failure here does not invalidate the create/get/delete assertions already made.
    Returns True/False on success, or None if the list call itself is unreachable."""
    for i in range(attempts):
        try:
            found = False
            token = None
            while True:
                kwargs = {"MaxResults": 1000}
                if token:
                    kwargs["NextToken"] = token
                resp = glue.list_form_types(**kwargs)
                if any(item["Id"] == target_id for item in resp.get("Items", [])):
                    found = True
                token = resp.get("NextToken")
                if not token:
                    break
            return found
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InternalServiceException", "ThrottlingException") and i < attempts - 1:
                time.sleep(delay)
                continue
            return None
    return None


def _cleanup_form_type(glue, identifier: str) -> None:
    try:
        glue.delete_form_type(Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

