"""share-directory-with-owner-account-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "share-directory-with-owner-account-rejected"
GROUP = "negative-classes"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Ds-Pw9!"
_DIR_ACTIVE_TIMEOUT_S = 3600.0
# A syntactically valid but unaffiliated account id, used only as an opaque HANDSHAKE share target:
# ShareDirectory does not validate that the target account exists at request time.
_OTHER_ACCOUNT_ID = "111122223333"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ShareDirectory naming the directory's own account as the target is rejected and creates no
    share record for it, while the identical call naming a different account succeeds and is
    visible, so the refusal is the share target's and not ShareDirectory's."""
    ds = ctx.client("ds")
    owner = ctx.client("sts").get_caller_identity()["Account"]

    directory_id = _create_microsoft_ad(ctx, ds)
    ctx.on_cleanup(lambda: _delete_directory(ds, directory_id))
    _wait_for_directory_stage(ds, directory_id, {"Active"}, _DIR_ACTIVE_TIMEOUT_S)

    control_key = ctx.unique_name("sim2real-control-")
    ds.add_tags_to_resource(ResourceId=directory_id, Tags=[{"Key": control_key, "Value": "ok"}])
    control = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    assert {"Key": control_key, "Value": "ok"} in control, (
        f"tagging the active directory did not round-trip: {control!r}"
    )

    # Positive control on the same wiring as the negative below: the identical ShareDirectory
    # call naming a different, genuinely distinct account succeeds and is visible.
    ds.share_directory(
        DirectoryId=directory_id,
        ShareMethod="HANDSHAKE",
        ShareTarget={"Id": _OTHER_ACCOUNT_ID, "Type": "ACCOUNT"},
    )
    ctx.on_cleanup(lambda: _unshare(ds, directory_id, _OTHER_ACCOUNT_ID))
    before = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    assert any(s["SharedAccountId"] == _OTHER_ACCOUNT_ID for s in before), (
        f"ShareDirectory to a distinct account produced no share record: {before!r}"
    )

    code, message = _error(
        lambda: ds.share_directory(
            DirectoryId=directory_id,
            ShareMethod="HANDSHAKE",
            ShareTarget={"Id": owner, "Type": "ACCOUNT"},
        )
    )
    assert code == "InvalidTargetException", (
        f"expected InvalidTargetException sharing with the owner account, got {code!r}: {message!r}"
    )
    expected = (
        f"The Target AWS account ID {owner} you specified cannot be the same as the "
        "directory owner AWS account ID."
    )
    assert message.split(" : RequestId:")[0] == expected, (
        f"unexpected InvalidTargetException message: {message!r} (expected {expected!r})"
    )

    shared = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    assert not any(s["SharedAccountId"] == owner for s in shared), (
        f"a share record for the owner account appeared despite the rejected share: {shared!r}"
    )
    assert any(s["SharedAccountId"] == _OTHER_ACCOUNT_ID for s in shared), (
        f"the earlier legitimate share to a distinct account disappeared after the rejected "
        f"self-share: {shared!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _unshare(ds, directory_id, target_account_id) -> None:
    """Remove the positive-control share so it does not block the directory's teardown."""
    try:
        ds.unshare_directory(
            DirectoryId=directory_id, UnshareTarget={"Id": target_account_id, "Type": "ACCOUNT"}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        shares = ds.describe_shared_directories(OwnerDirectoryId=directory_id).get(
            "SharedDirectories", []
        )
        if not any(s["SharedAccountId"] == target_account_id for s in shares):
            return
        time.sleep(5.0)
    raise AssertionError(f"share with {target_account_id} did not clear within 120s")


def _create_microsoft_ad(ctx, ds) -> str:
    """A Standard Microsoft AD in two zones of the run's network that Directory Service accepts."""
    net = ctx.network()
    zones = net.availability_zones
    name = ctx.unique_name("sim2realds").lower() + ".test"
    last = None
    for i in range(len(zones) - 1):
        for j in range(i + 1, len(zones)):
            try:
                return ds.create_microsoft_ad(
                    Name=name,
                    Password=_PASSWORD,
                    Edition="Standard",
                    VpcSettings={
                        "VpcId": net.vpc_id,
                        "SubnetIds": [net.subnets[zones[i]], net.subnets[zones[j]]],
                    },
                )["DirectoryId"]
            except ClientError as exc:
                # Directory Service serves only some zones of a region; try the next pair.
                if "Availability Zone" not in exc.response["Error"].get("Message", ""):
                    raise
                last = exc
    raise AssertionError(f"no pair of the network's zones {zones!r} hosts a directory: {last!r}")


def _wait_for_directory_stage(ds, directory_id, target_stages, timeout_s, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        stage = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0][
            "Stage"
        ]
        if stage in target_stages:
            return
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} entered terminal stage {stage}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s "
        f"(last stage={stage})"
    )


def _delete_directory(ds, directory_id, timeout_s=1700.0, interval_s=30.0) -> None:
    """Delete the directory and wait until it is actually gone: DS holds the domain controllers'
    ENIs in the run's shared network until the delete completes, and that network's own teardown
    cannot remove its subnets while those ENIs are still attached."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not desc or desc[0]["Stage"] in {"Active", "Failed", "Inoperable"}:
            break
        time.sleep(interval_s)
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise
    while time.monotonic() < deadline:
        try:
            desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not desc or desc[0].get("Stage") == "Deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} was not deleted within {timeout_s:.0f}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
