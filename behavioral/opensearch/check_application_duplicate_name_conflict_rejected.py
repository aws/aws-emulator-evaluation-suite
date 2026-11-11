"""application-duplicate-name-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-duplicate-name-conflict-rejected"
GROUP = "e2e"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second OpenSearch application with a name that already exists is
    rejected with ConflictException, leaves the original application untouched, and a
    fresh unique name still succeeds (positive control) in the same account/region."""
    osv = ctx.client("opensearch")

    name = _clean_name(ctx.unique_name("sim2osdup-"), 30)
    try:
        first = osv.create_application(name=name, tagList=[{"Key": "sim2real", "Value": CHECK}])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DisabledOperationException":
            raise AssertionError(
                "OpenSearch Applications feature is not enabled for this account/region"
            ) from exc
        raise
    first_id = first["id"]
    ctx.on_cleanup(lambda: _delete_application(ctx, first_id))
    _wait_application_active(ctx, first_id, timeout_s=300.0)

    try:
        dup = osv.create_application(name=name, tagList=[{"Key": "sim2real", "Value": CHECK}])
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
    else:
        # An over-permissive target that accepts the duplicate still leaked a real
        # resource; track it for cleanup before failing the check.
        ctx.on_cleanup(lambda: _delete_application(ctx, dup["id"]))
        raise AssertionError(f"expected ConflictException for duplicate name, but CreateApplication returned {dup!r}")
    assert code == "ConflictException", f"expected ConflictException for duplicate name, got {code!r}"
    expected = f"Application name {name} already exists"
    assert message == expected, f"duplicate-name message: expected {expected!r}, got {message!r}"

    # Effect absent: the original application is untouched by the failed duplicate create.
    unchanged = osv.get_application(id=first_id)
    assert unchanged["status"] == "ACTIVE", f"expected original application to stay ACTIVE, got {unchanged['status']!r}"
    assert unchanged["name"] == name, f"expected original application name {name!r} unchanged, got {unchanged['name']!r}"

    # Positive control: a fresh unique name still succeeds.
    other_name = _clean_name(ctx.unique_name("sim2osdup2-"), 30)
    second = osv.create_application(name=other_name, tagList=[{"Key": "sim2real", "Value": CHECK}])
    second_id = second["id"]
    ctx.on_cleanup(lambda: _delete_application(ctx, second_id))
    active_second = _wait_application_active(ctx, second_id, timeout_s=300.0)
    assert active_second["name"] == other_name, f"expected fresh application name {other_name!r}, got {active_second['name']!r}"
    assert second_id != first_id, f"fresh create returned the same id as the original: {second_id!r}"


def _clean_name(raw: str, max_len: int) -> str:
    cleaned = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:max_len]


def _delete_application(ctx, app_id: str) -> None:
    osv = ctx.client("opensearch")
    try:
        osv.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_application_active(ctx, app_id: str, timeout_s: float, interval_s: float = 10.0) -> dict:
    osv = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osv.get_application(id=app_id)
        if last["status"] == "ACTIVE":
            return last
        if last["status"] == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} never became ACTIVE within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
