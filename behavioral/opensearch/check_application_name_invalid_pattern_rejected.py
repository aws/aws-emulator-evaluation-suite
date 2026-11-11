"""application-name-invalid-pattern-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "application-name-invalid-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplication with a name outside ^[a-z][a-z0-9\\-]+$ fails with ValidationException and the
    exact message and is not listed, while the cleaned lower-case name is created."""
    client = ctx.client("opensearch")
    base = ctx.unique_name("sim2real-badname-")
    invalid_name = "Bad_" + base.replace("-", "_").upper()[:20]

    code, message = _error(lambda: client.create_application(name=invalid_name))
    assert code == "ValidationException", f"expected ValidationException for invalid name, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{invalid_name}' at 'name' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-z][a-z0-9\\-]+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the specific rejected name never shows up in the listing. (We only check
    # for the exact rejected name rather than diffing the full listing, since other checks may
    # be creating/deleting unrelated applications concurrently in the same account.)
    after = {a["name"] for a in _list_all_applications(ctx)}
    assert invalid_name not in after, "an application was created despite the rejected invalid name"

    # Positive control: a name satisfying the pattern succeeds.
    valid_name = _sanitize(base)
    created = client.create_application(
        name=valid_name,
        tagList=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    app_id = created["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: client.delete_application(id=app_id)))
    _wait_application_status(ctx, app_id, {"ACTIVE"}, {"FAILED"})

    got = client.get_application(id=app_id)
    assert got["name"] == valid_name, f"expected application name {valid_name!r}, got {got['name']!r}"

    client.delete_application(id=app_id)
    _wait_application_deleted(ctx, app_id)
    # A second delete of the removed application is an idempotent success: any error raises here.
    client.delete_application(id=app_id)


def _sanitize(raw: str) -> str:
    lowered = raw.lower().replace("_", "-")
    cleaned = "".join(ch for ch in lowered if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:30]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_applications(ctx):
    client = ctx.client("opensearch")
    out = []
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_applications(**kwargs)
        out.extend(page.get("ApplicationSummaries", []))
        next_token = page.get("nextToken")
        if not next_token:
            return out


def _wait_application_status(ctx, app_id, ok_statuses, terminal_bad_statuses, timeout_s=600.0):
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        got = client.get_application(id=app_id)
        last = got.get("status")
        if last in ok_statuses:
            return got
        if last in terminal_bad_statuses:
            raise AssertionError(f"application {app_id} reached bad status {last!r}: {got!r}")
        time.sleep(5)
    raise AssertionError(f"application {app_id} did not reach {ok_statuses} within {timeout_s}s (last={last!r})")


def _wait_application_deleted(ctx, app_id, timeout_s=600.0):
    from botocore.exceptions import ClientError

    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = client.get_application(id=app_id).get("status")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            raise
        if last_status == "FAILED":
            raise AssertionError(f"application {app_id} reached FAILED while awaiting removal")
        time.sleep(5)
    raise AssertionError(f"application {app_id} was not deleted within {timeout_s}s (last status={last_status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
