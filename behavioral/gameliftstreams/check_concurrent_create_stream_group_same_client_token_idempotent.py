"""concurrent-create-stream-group-same-client-token-idempotent."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-stream-group-same-client-token-idempotent"
GROUP = "concurrency"
SERVICES = ["gameliftstreams"]

_TERMINAL_STATUSES = {"ACTIVE", "ACTIVE_WITH_ERRORS", "ERROR"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateStreamGroup calls sharing one ClientToken and identical parameters all resolve to the
    same stream group, and ListStreamGroups holds exactly one group with that description.
    """
    gl = ctx.client("gameliftstreams")
    token = uuid.uuid4().hex + uuid.uuid4().hex
    desc = ctx.unique_name("sim2real-behav-gls-race-sg-")
    created_arns: set[str] = set()

    def racer():
        try:
            resp = gl.create_stream_group(
                ClientToken=token,
                Description=desc,
                StreamClass="gen6n_small",
                Tags={"sim2real": CHECK},
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ServiceQuotaExceededException":
                raise AssertionError(
                    f"account has no GPU quota in this Region ({e}); GameLift Streams GPU "
                    "quotas default to 0 and must be explicitly requested"
                )
            if code == "ConflictException":
                return _resolve_by_description(gl, desc)
            raise
        created_arns.add(resp["Arn"])
        return resp

    try:
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(lambda _: racer(), range(5)))
    finally:
        # Best-effort safety net: the body below deletes synchronously once stable,
        # but if the body itself raises first, still attempt cleanup.
        for arn in created_arns:
            ctx.on_cleanup(lambda arn=arn: _safe(lambda: gl.delete_stream_group(Identifier=arn)))

    arns = {r["Arn"] for r in results}
    assert len(arns) == 1, f"expected all racers to resolve to one stream group, got {arns}"
    sg_arn = next(iter(arns))

    items = _list_all_stream_groups(gl)
    matching = [i for i in items if i.get("Description") == desc]
    assert len(matching) == 1, f"expected exactly one stream group with description {desc!r}, found {len(matching)}"

    _poll_until(
        lambda: gl.get_stream_group(Identifier=sg_arn).get("Status"),
        lambda status: status in _TERMINAL_STATUSES,
        timeout_s=180.0,
        interval_s=5.0,
    )
    gl.delete_stream_group(Identifier=sg_arn)


def _resolve_by_description(gl, desc, timeout_s=30.0, interval_s=1.0):
    """Recover from ConflictException per its own message: a sibling racer's create is
    landing concurrently; poll ListStreamGroups until it is visible."""
    deadline = time.monotonic() + timeout_s
    last_count = 0
    while time.monotonic() < deadline:
        items = _list_all_stream_groups(gl)
        matching = [i for i in items if i.get("Description") == desc]
        last_count = len(matching)
        if last_count == 1:
            return matching[0]
        time.sleep(interval_s)
    raise AssertionError(
        f"ConflictException on CreateStreamGroup but no single stream group with "
        f"description {desc!r} appeared within {timeout_s}s (found {last_count})"
    )


def _list_all_stream_groups(gl):
    items = []
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = gl.list_stream_groups(**kwargs)
        items.extend(page.get("Items", []))
        token = page.get("NextToken")
        if not token:
            break
    return items


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
