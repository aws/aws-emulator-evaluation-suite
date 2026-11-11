"""delete-packaging-configuration-state-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-packaging-configuration-state-transition"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePackagingConfiguration returns 204 No Content and the configuration transitions to gone
    asynchronously, eventually resolving to NotFoundException on Describe."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(Id=group_id, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    config_id = ctx.unique_name("sim2real-mpvod-cfg-")
    mpv.create_packaging_configuration(
        Id=config_id,
        PackagingGroupId=group_id,
        HlsPackage={"HlsManifests": [{"ManifestName": "index"}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _best_effort_delete_config(mpv, config_id))

    resp = mpv.delete_packaging_configuration(Id=config_id)
    status_code = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status_code == 204, f"expected 204 No Content, got {status_code}"

    expected_not_found = f"PackagingConfig with id={config_id} not found"
    gone_message = _poll_until_config_not_found(ctx, config_id, timeout_s=60.0)
    assert gone_message == expected_not_found, (
        f"expected DescribePackagingConfiguration message {expected_not_found!r}, "
        f"got {gone_message!r}"
    )

    second_delete_code, second_delete_message = _error(
        lambda: mpv.delete_packaging_configuration(Id=config_id)
    )
    assert second_delete_code == "NotFoundException", (
        f"expected a second delete of the now-gone {config_id} to fail with "
        f"NotFoundException, got {second_delete_code}"
    )
    assert second_delete_message == expected_not_found, (
        f"expected second-delete message {expected_not_found!r}, got {second_delete_message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _best_effort_delete_config(mpv, config_id: str) -> None:
    try:
        mpv.delete_packaging_configuration(Id=config_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until_config_not_found(ctx, config_id: str, timeout_s: float = 60.0) -> str:
    """Describe until NotFoundException and return its message; raise on timeout."""
    mpv = ctx.client("mediapackage-vod")
    deadline = time.monotonic() + timeout_s
    code = None
    while time.monotonic() < deadline:
        try:
            mpv.describe_packaging_configuration(Id=config_id)
            code = None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return e.response["Error"].get("Message")
        time.sleep(2.0)
    raise AssertionError(
        f"packaging configuration {config_id} did not become NotFoundException within "
        f"{timeout_s}s (last observed code: {code})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
