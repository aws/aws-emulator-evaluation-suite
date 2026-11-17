"""list-memories-maxresults-range-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-memories-maxresults-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]

_RANGE_REJECTED = (
    "ValidationException",
    "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
    "Member must have value greater than or equal to 1",
)

_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING")


def _memory_name(ctx):
    raw = ctx.unique_name("sim2realmem")
    cleaned = "".join(c for c in raw if c.isalnum())
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def expect_error(fn, code, message):
    actual_code, actual_message = _error(fn)
    assert actual_code == code, f"expected {code!r}, got {actual_code!r} ({actual_message!r})"
    assert actual_message == message, f"expected message {message!r}, got {actual_message!r}"


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value {last!r}")


def _delete_memory(control, memory_id):
    """Wait past any transitional status, then delete; tolerate the memory already being gone."""
    try:
        status = _poll_until(
            lambda: control.get_memory(memoryId=memory_id)["memory"]["status"],
            lambda s: s not in _TRANSITIONAL,
            timeout_s=50.0,
            interval_s=5.0,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETING":
        return
    try:
        control.delete_memory(memoryId=memory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMemories sent maxResults=0 with client-side validation off is refused with
    ValidationException and the range's exact message; sent maxResults=1 it pages back the
    created memory's own id, arn, status and timestamps, one per page.
    """
    control = ctx.client("bedrock-agentcore-control")
    unvalidated = ctx.client("bedrock-agentcore-control", config=Config(parameter_validation=False))

    name = _memory_name(ctx)
    created = control.create_memory(
        name=name, eventExpiryDuration=7, tags={"sim2real": CHECK}
    )["memory"]
    memory_id = created["id"]
    memory_arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_memory(control, memory_id))

    active = _poll_until(
        lambda: control.get_memory(memoryId=memory_id)["memory"],
        lambda m: m["status"] != "CREATING",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert active["status"] == "ACTIVE", f"expected memory to reach ACTIVE, got {active['status']!r}"

    expect_error(lambda: unvalidated.list_memories(maxResults=0), *_RANGE_REJECTED)

    found = None
    token = None
    while found is None:
        kwargs = {"maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        page = control.list_memories(**kwargs)
        items = page["memories"]
        token = page.get("nextToken")
        if any(m.get("id") == memory_id for m in items):
            assert len(items) == 1, (
                f"maxResults=1 returned {len(items)} memories on the page holding ours: {items!r}"
            )
            found = items[0]
        elif not token:
            raise AssertionError(
                f"memory {memory_id} never appeared while paging ListMemories with maxResults=1"
            )

    assert found["id"] == memory_id, f"expected id {memory_id!r}, got {found['id']!r}"
    assert found["arn"] == memory_arn, f"expected arn {memory_arn!r}, got {found['arn']!r}"
    assert found["status"] == "ACTIVE", f"expected status 'ACTIVE', got {found['status']!r}"
    assert found["createdAt"] == active["createdAt"], (
        f"expected createdAt {active['createdAt']!r}, got {found['createdAt']!r}"
    )
    assert found["updatedAt"] == active["updatedAt"], (
        f"expected updatedAt {active['updatedAt']!r}, got {found['updatedAt']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
