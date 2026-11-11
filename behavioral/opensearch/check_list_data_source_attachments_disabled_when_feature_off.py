"""list-data-source-attachments-disabled-when-feature-off."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-data-source-attachments-disabled-when-feature-off"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataSourceAttachments for an ACTIVE application without attachments returns an empty list, while an
    unknown application id fails with ResourceNotFoundException and its exact message.
    """
    client = ctx.client("opensearch")
    app_name = _app_name(ctx)
    try:
        created = client.create_application(
            name=app_name, tagList=[{"Key": "sim2real-check", "Value": CHECK}]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DisabledOperationException":
            raise AssertionError(
                "OpenSearch Applications feature is not enabled for this account/region: "
                "cannot create the application prerequisite this check needs"
            ) from exc
        raise
    app_id = created["id"]
    ctx.on_cleanup(lambda: client.delete_application(id=app_id))
    _wait_application_active(ctx, client, app_id)

    # Positive control: a real, active application with no data-source attachments returns
    # an ordinary empty list -- not an exception of any kind.
    listed = client.list_data_source_attachments(id=app_id)
    assert listed["attachments"] == [], f"expected an empty attachments list, got {listed['attachments']}"

    # Contrast: the same operation against an application id that genuinely does not exist
    # raises ResourceNotFoundException -- proving the id is actually resolved/checked, and
    # that the empty list above is not itself evidence of a feature being silently disabled.
    # A hand-built string (e.g. "sim2real-missing-app-...") fails *format* validation before
    # ever reaching an existence check (ValidationException) -- so instead we mutate the real,
    # server-issued app_id in place (same length, same character class, guaranteed-different
    # value) to get a syntactically valid id that is certain not to exist.
    missing_id = _mutate_id(app_id)
    got = _error(lambda: client.list_data_source_attachments(id=missing_id))
    expected = ("ResourceNotFoundException", f"Application {missing_id} not found")
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # Effect-absent / positive-control-in-one: the application that the successful call named
    # is untouched and still perfectly describable.
    still = client.get_application(id=app_id)
    assert still["status"] == "ACTIVE", f"expected app {app_id} to still be ACTIVE, got {still['status']}"
    assert still["id"] == app_id, f"expected GetApplication to echo id {app_id}, got {still['id']}"


def _app_name(ctx) -> str:
    raw = ctx.unique_name("sim2realapp")
    cleaned = "".join(c for c in raw.lower() if c.isalnum())[:30]
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned[:29]
    return cleaned


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING an id real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _mutate_id(app_id: str) -> str:
    """Flip one character of a real, server-issued id to a sibling from the same character
    class (digit or letter), preserving length and apparent format so the mutated value still
    passes format validation but is virtually certain not to exist.
    """
    chars = list(app_id)
    for i, ch in enumerate(chars):
        if ch.isdigit():
            chars[i] = str((int(ch) + 1) % 10)
            return "".join(chars)
        if ch.isalpha():
            base = ord("a") if ch.islower() else ord("A")
            chars[i] = chr((ord(ch) - base + 1) % 26 + base)
            return "".join(chars)
    raise AssertionError(f"could not mutate id (no alnum chars): {app_id!r}")


def _wait_application_active(ctx, client, app_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = client.get_application(id=app_id)
        last = resp["status"]
        if last == "ACTIVE":
            return
        if last == "FAILED":
            raise AssertionError(f"application entered FAILED state while waiting: {resp}")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} never became ACTIVE, last status={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
