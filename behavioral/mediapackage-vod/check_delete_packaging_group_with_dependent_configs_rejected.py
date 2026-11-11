"""delete-packaging-group-with-dependent-configs-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-packaging-group-with-dependent-configs-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage-vod"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePackagingGroup fails UnprocessableEntityException with the exact message while a
    PackagingConfiguration references the group, which stays describable; once the configuration is
    deleted, the same delete succeeds and DescribePackagingGroup fails NotFoundException."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(Id=group_id)
    ctx.on_cleanup(lambda: _best_effort_delete_group(mpv, group_id))

    config_id = ctx.unique_name("sim2real-mpvod-cfg-")
    mpv.create_packaging_configuration(
        Id=config_id,
        PackagingGroupId=group_id,
        HlsPackage={"HlsManifests": [{"ManifestName": "index"}]},
    )
    ctx.on_cleanup(lambda: _best_effort_delete_config(mpv, config_id))

    in_use = ("UnprocessableEntityException", "id cannot be deleted because it has attached packaging configurations")
    _assert_rejected(
        lambda: mpv.delete_packaging_group(Id=group_id),
        in_use[0],
        in_use[1],
        "DeletePackagingGroup while a dependent PackagingConfiguration still references the group",
    )

    # Effect absent: the group still exists.
    described = mpv.describe_packaging_group(Id=group_id)
    assert described["Id"] == group_id, (
        f"expected packaging group {group_id!r} to remain intact after the rejected delete, "
        f"got {described.get('Id')!r}"
    )

    # Positive control: removing the dependency first lets the delete succeed.
    mpv.delete_packaging_configuration(Id=config_id)
    _poll_until_config_not_found(ctx, config_id, timeout_s=60.0)
    mpv.delete_packaging_group(Id=group_id)
    _poll_until_group_not_found(ctx, group_id, timeout_s=60.0)


def _assert_rejected(fn, expected_code: str, expected_message: str, what: str) -> None:
    try:
        result = fn()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        actual = e.response["Error"]["Message"]
        assert code == expected_code, f"{what}: expected {expected_code!r}, got {code!r}"
        assert actual == expected_message, f"{what}: expected message {expected_message!r}, got {actual!r}"
        return
    raise AssertionError(f"{what}: expected {expected_code!r}, but the call succeeded and returned {result!r}")


def _best_effort_delete_config(mpv, config_id: str) -> None:
    try:
        mpv.delete_packaging_configuration(Id=config_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _best_effort_delete_group(mpv, group_id: str) -> None:
    try:
        mpv.delete_packaging_group(Id=group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until_config_not_found(ctx, config_id: str, timeout_s: float = 60.0) -> None:
    _poll_until_not_found(
        lambda: ctx.client("mediapackage-vod").describe_packaging_configuration(Id=config_id),
        f"PackagingConfig with id={config_id} not found",
        timeout_s,
    )


def _poll_until_group_not_found(ctx, group_id: str, timeout_s: float = 60.0) -> None:
    _poll_until_not_found(
        lambda: ctx.client("mediapackage-vod").describe_packaging_group(Id=group_id),
        f"PackagingGroup with id={group_id} not found",
        timeout_s,
    )


def _poll_until_not_found(describe, expected_message: str, timeout_s: float) -> None:
    """Poll ``describe`` until it raises NotFoundException with ``expected_message``."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            describe()
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise
            actual = e.response["Error"]["Message"]
            assert actual == expected_message, f"expected message {expected_message!r}, got {actual!r}"
            return
        time.sleep(2.0)
    raise AssertionError(f"still describes {timeout_s}s after its delete; expected {expected_message!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
