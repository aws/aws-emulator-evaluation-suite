"""packaging-group-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "packaging-group-lifecycle"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A packaging group transitions create -> describable/listable -> deleted (async, eventually 404),
    and the dead id is provably unusable afterward."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")

    created = mpv.create_packaging_group(Id=group_id)
    ctx.on_cleanup(lambda: _best_effort_delete_group(mpv, group_id))
    assert created["Id"] == group_id, f"expected Id {group_id!r}, got {created['Id']!r}"
    assert created["Arn"].endswith(group_id), f"expected Arn to end with {group_id!r}, got {created['Arn']!r}"
    assert created["DomainName"], "expected a non-empty system-assigned egress domain"

    described = mpv.describe_packaging_group(Id=group_id)
    assert described["Id"] == group_id, f"expected Id {group_id!r}, got {described['Id']!r}"
    assert described["ApproximateAssetCount"] == 0, (
        f"expected a freshly created group to have 0 assets, got {described['ApproximateAssetCount']!r}"
    )
    assert described["DomainName"] == created["DomainName"], (
        f"expected DomainName to stay {created['DomainName']!r}, got {described['DomainName']!r}"
    )

    listed_ids = {g["Id"] for g in mpv.list_packaging_groups()["PackagingGroups"]}
    assert group_id in listed_ids, f"expected {group_id!r} in list_packaging_groups, got {listed_ids!r}"

    delete_resp = mpv.delete_packaging_group(Id=group_id)
    status_code = delete_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status_code == 204, f"expected 204 No Content from delete, got {status_code}"
    expected_not_found = f"PackagingGroup with id={group_id} not found"
    gone_message = _poll_until_group_not_found(ctx, group_id, timeout_s=60.0)
    assert gone_message == expected_not_found, (
        f"expected DescribePackagingGroup message {expected_not_found!r}, got {gone_message!r}"
    )

    dead_delete_code, dead_delete_message = _error(lambda: mpv.delete_packaging_group(Id=group_id))
    assert dead_delete_code == "NotFoundException", (
        f"expected a second delete of the same dead id to raise NotFoundException, got {dead_delete_code!r}"
    )
    assert dead_delete_message == expected_not_found, (
        f"expected second-delete message {expected_not_found!r}, got {dead_delete_message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _best_effort_delete_group(mpv, group_id: str) -> None:
    try:
        mpv.delete_packaging_group(Id=group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until_group_not_found(ctx, group_id: str, timeout_s: float = 60.0) -> str:
    """Describe until NotFoundException and return its message; raise on timeout."""
    mpv = ctx.client("mediapackage-vod")
    deadline = time.monotonic() + timeout_s
    code = None
    while time.monotonic() < deadline:
        try:
            mpv.describe_packaging_group(Id=group_id)
            code = None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return e.response["Error"].get("Message")
        time.sleep(2.0)
    raise AssertionError(
        f"packaging group {group_id} did not become NotFoundException within {timeout_s}s "
        f"(last observed code: {code})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
