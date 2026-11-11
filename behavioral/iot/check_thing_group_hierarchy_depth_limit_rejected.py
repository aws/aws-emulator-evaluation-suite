"""thing-group-hierarchy-depth-limit-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "thing-group-hierarchy-depth-limit-rejected"
GROUP = 'thing-group'
SERVICES = ['iot']

# AWS IoT fixed service limit (non-adjustable, not an account
# quota): a thing-group hierarchy is at most 7 levels deep. Probe one level past that.
_MAX_DEPTH = 7
_PROBE_DEPTH = _MAX_DEPTH + 1


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_group_settled(iot, name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> None:
    """Teardown: delete a thing group, retrying while a just-deleted child is still visible to
    the parent (InvalidRequestException), and tolerating a group that is already gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.delete_thing_group(thingGroupName=name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A thing-group hierarchy is capped at 7 levels: the 8th nested group fails InvalidRequestException with the
    exact message and is never created, while depth 7 stays intact and still accepts a sibling."""
    iot = ctx.client("iot")
    base = ctx.unique_name("sim2real-behav-group-depth-")

    created: list[str] = []
    parent = None
    for level in range(1, _PROBE_DEPTH + 1):
        name = f"{base}-L{level}"
        kwargs = {"thingGroupName": name}
        if parent is not None:
            kwargs["parentGroupName"] = parent
        if level <= _MAX_DEPTH:
            iot.create_thing_group(**kwargs)
            # LIFO cleanup deletes the deepest group first — a group with children cannot be deleted.
            ctx.on_cleanup(lambda _n=name: _delete_group_settled(iot, _n))
            created.append(name)
            parent = name
            continue

        # Break exactly one thing: one level too deep. CreateThingGroup models only
        # InvalidRequestException / ResourceAlreadyExistsException / ThrottlingException /
        # InternalFailureException as client-visible failures, so InvalidRequestException is the
        # only code the depth refusal can carry. Confirmed against real AWS: an 8th-level
        # CreateThingGroup under a 7-deep hierarchy raises InvalidRequestException.
        code, code_message = _error(lambda _k=kwargs: iot.create_thing_group(**_k))
        assert code == "InvalidRequestException", (
            f"creating a level-{level} thing group under a {_MAX_DEPTH}-deep hierarchy must be "
            f"refused with InvalidRequestException, got {code}"
        )
        assert code_message == f"Cannot create child group for parent group : {parent}. Depth of group hierarchy exceeds allowed max depth :{_MAX_DEPTH}", (
            f"expected the exact {code} message, got {code_message!r}"
        )
        # Effect absent: the over-deep group must not exist.
        absent, absent_message = _error(lambda _n=name: iot.describe_thing_group(thingGroupName=_n))
        assert absent == "ResourceNotFoundException", (
            f"the refused group {name} must not have been created, DescribeThingGroup gave {absent}"
        )
        assert absent_message == f"ThingGroup {ctx.account}:{name} not found.", (
            f"expected the exact {absent} message, got {absent_message!r}"
        )

    assert len(created) == _MAX_DEPTH, f"setup: expected {_MAX_DEPTH} groups, created {len(created)}"
    deepest = created[-1]
    assert (
        iot.describe_thing_group(thingGroupName=deepest)["thingGroupMetadata"]["parentGroupName"]
        == created[-2]
    ), f"the level-{_MAX_DEPTH} group must still report its parent {created[-2]}"

    # Control: the hierarchy is not wedged — a SIBLING at the deepest allowed level still works.
    sibling = f"{base}-L{_MAX_DEPTH}b"
    iot.create_thing_group(thingGroupName=sibling, parentGroupName=created[-2])
    ctx.on_cleanup(lambda _n=sibling: _delete_group_settled(iot, _n))
    assert (
        iot.describe_thing_group(thingGroupName=sibling)["thingGroupMetadata"]["parentGroupName"]
        == created[-2]
    ), f"a sibling at the maximum allowed depth must be accepted under {created[-2]}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
