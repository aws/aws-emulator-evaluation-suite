"""deploy-ec2-1-volume-deletion-policy-snapshot-vs-retain."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-1-volume-deletion-policy-snapshot-vs-retain"

GROUP = "deploy-cfn-ec2-network"

SERVICES = ["cloudformation", "ec2"]

VOLUME_SIZE_GIB = 1


def _template(tag: str) -> str:
    t = [{"Key": "sim2real", "Value": tag}]
    vol = {"AvailabilityZone": {"Ref": "Az"}, "Size": VOLUME_SIZE_GIB, "VolumeType": "gp3"}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Az": {"Type": "String"}},
        "Resources": {
            "SnapVol": {"Type": "AWS::EC2::Volume", "DeletionPolicy": "Snapshot",
                        "Properties": {**vol, "Tags": t + [{"Key": "role", "Value": "snap"}]}},
            "KeepVol": {"Type": "AWS::EC2::Volume", "DeletionPolicy": "Retain",
                        "Properties": {**vol, "Tags": t + [{"Key": "role", "Value": "keep"}]}},
        },
        "Outputs": {
            "SnapVolId": {"Value": {"Ref": "SnapVol"}},
            "KeepVolId": {"Value": {"Ref": "KeepVol"}},
        },
    })


def _stack_events(cfn, stack: str) -> list[dict[str, Any]]:
    """Every event for a stack, oldest first, paginated."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page.get("StackEvents", []))
        token = page.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _wait_stack_status(cfn, stack: str, timeout_s: float = 1500.0) -> dict[str, Any]:
    """Poll until the stack leaves every *_IN_PROGRESS status."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack)["Stacks"][0]
        if not last["StackStatus"].endswith("_IN_PROGRESS"):
            return last
        time.sleep(5)
    raise AssertionError(f"stack {stack!r} still in progress after {timeout_s}s: "
                         f"{(last or {}).get('StackStatus')!r}")


def _snapshots_of(ec2, volume_id: str) -> list[dict[str, Any]]:
    """Own snapshots taken FROM one volume -- a query only this check's volume can satisfy."""
    out: list[dict[str, Any]] = []
    for page in ec2.get_paginator("describe_snapshots").paginate(
            OwnerIds=["self"], Filters=[{"Name": "volume-id", "Values": [volume_id]}]):
        out.extend(page.get("Snapshots", []))
    return out


def _volume_ids_from_events(cfn, stack_id: str) -> dict[str, str]:
    ids: dict[str, str] = {}
    try:
        for e in _stack_events(cfn, stack_id):
            pid = e.get("PhysicalResourceId") or ""
            if e.get("LogicalResourceId") in ("SnapVol", "KeepVol") and pid.startswith("vol-"):
                ids[e["LogicalResourceId"]] = pid
    except Exception as exc:  # noqa: BLE001
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"could not read stack events for {stack_id}: {exc!r}"
            ) from exc
    return ids


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_id)
        st = _wait_stack_status(cfn, stack_id)
        if st["StackStatus"] != "DELETE_COMPLETE":
            raise RuntimeError(f"stack {stack_id} ended {st['StackStatus']}: "
                               f"{st.get('StackStatusReason')}")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_id} delete failed: {exc!r}") from exc


def _reap_what_the_policies_left(cfn, ec2, holder: dict[str, str]) -> None:
    """Runs AFTER the stack delete (registered first, LIFO): the Retain volume and the
    DeletionPolicy snapshot both outlive the stack by design, so the check owns deleting them."""
    _leaks: list = []
    stack_id = holder.get("stack_id")
    if not stack_id:
        if _leaks:
            raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                (e for _, e in _leaks if e is not None), None
            )
        return
    ids = _volume_ids_from_events(cfn, stack_id)
    for vol in ids.values():
        try:
            for snap in _snapshots_of(ec2, vol):
                ec2.delete_snapshot(SnapshotId=snap["SnapshotId"])
        except Exception as exc:  # noqa: BLE001
            teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if (
                teardown_code not in ("InvalidSnapshot.NotFound",)
                and not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
            ):
                _leaks.append((f"snapshot of {vol} not deleted: {exc!r}", exc))
        deadline = time.monotonic() + 300
        while True:
            try:
                ec2.delete_volume(VolumeId=vol)
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "InvalidVolume.NotFound":
                    break
                if time.monotonic() > deadline:
                    _leaks.append((f"volume {vol} not deleted: {code}", exc))
                    break
                time.sleep(10)
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


def _settle_code(fn, want: str, timeout_s: float = 180.0) -> tuple[str | None, str | None]:
    deadline = time.monotonic() + timeout_s
    code = message = None
    while time.monotonic() < deadline:
        try:
            fn()
            code = "<call succeeded>"
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
        if code == want:
            return code, message
        time.sleep(5)
    return code, message




@tags("cap:c3", "cap:c4", "concern:deploy", "plane:control", "axis:happy-path")
def run(ctx) -> None:
    """delete-stack honours each EBS volume's DeletionPolicy independently: the Snapshot volume
    is snapshotted and then deleted, its Retain sibling survives untouched and still 'available',
    and only the first leaves a snapshot behind.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert zones, "no available availability zone in this region"
    az = zones[0]

    holder: dict[str, str] = {}
    ctx.on_cleanup(lambda: _reap_what_the_policies_left(cfn, ec2, holder))

    name = ctx.unique_name("sim2real-xsvc-ec2vol-")
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=_template(name),
        Parameters=[{"ParameterKey": "Az", "ParameterValue": az}],
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))
    holder["stack_id"] = stack_id

    stack = _wait_stack_status(cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the two-volume stack ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    out = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    snap_vol, keep_vol = out["SnapVolId"], out["KeepVolId"]

    # 1. both volumes really exist, in the requested zone and size, before anything is deleted
    vols = {v["VolumeId"]: v for v in ec2.describe_volumes(
        VolumeIds=[snap_vol, keep_vol])["Volumes"]}
    for vid in (snap_vol, keep_vol):
        v = vols[vid]
        assert (v["State"], v["Size"], v["AvailabilityZone"]) == ("available", VOLUME_SIZE_GIB, az), (
            f"volume {vid} is {(v['State'], v['Size'], v['AvailabilityZone'])!r}, expected "
            f"('available', {VOLUME_SIZE_GIB}, {az!r})"
        )
    # 2. baseline: no snapshot of either volume exists yet, so any found later was made by delete
    assert _snapshots_of(ec2, snap_vol) == [] and _snapshots_of(ec2, keep_vol) == [], (
        "snapshots of the freshly created volumes already exist before delete-stack"
    )

    cfn.delete_stack(StackName=stack_id)
    deleted = _wait_stack_status(cfn, stack_id)
    assert deleted["StackStatus"] == "DELETE_COMPLETE", (
        f"delete-stack ended {deleted['StackStatus']!r}: {deleted.get('StackStatusReason')!r}"
    )
    events = _stack_events(cfn, stack_id)
    delete_trail = {(e["LogicalResourceId"], e["ResourceStatus"]) for e in events
                    if e["ResourceStatus"].startswith("DELETE")}

    # 3. CloudFormation reports the two policies as two different outcomes
    assert ("SnapVol", "DELETE_COMPLETE") in delete_trail, (
        f"the Snapshot-policy volume has no DELETE_COMPLETE event; delete events {delete_trail!r}"
    )
    assert ("KeepVol", "DELETE_SKIPPED") in delete_trail, (
        f"the Retain-policy volume has no DELETE_SKIPPED event; delete events {delete_trail!r}"
    )
    assert ("KeepVol", "DELETE_COMPLETE") not in delete_trail, (
        f"the Retain-policy volume reported DELETE_COMPLETE; delete events {delete_trail!r}"
    )

    # 4. exactly one snapshot was taken from the Snapshot-policy volume, and it completes
    deadline = time.monotonic() + 600
    snaps = _snapshots_of(ec2, snap_vol)
    while time.monotonic() < deadline and not (
            len(snaps) == 1 and snaps[0]["State"] == "completed"):
        time.sleep(2)
        snaps = _snapshots_of(ec2, snap_vol)
    assert [(s["VolumeId"], s["State"], s["VolumeSize"]) for s in snaps] == [
        (snap_vol, "completed", VOLUME_SIZE_GIB)], (
        f"DescribeSnapshots(volume-id={snap_vol}) returned "
        f"{[(s['SnapshotId'], s['State'], s['VolumeSize']) for s in snaps]!r}, expected exactly "
        f"one completed {VOLUME_SIZE_GIB} GiB snapshot"
    )

    # 5. ... and then the volume itself was deleted
    code, message = _settle_code(lambda: ec2.describe_volumes(VolumeIds=[snap_vol]),
                                 "InvalidVolume.NotFound")
    assert code == "InvalidVolume.NotFound", (
        f"the Snapshot-policy volume {snap_vol} answers describe_volumes with {code!r} after "
        f"DELETE_COMPLETE, expected 'InvalidVolume.NotFound'"
    )
    assert message == f"The volume '{snap_vol}' does not exist.", (
        f"DescribeVolumes InvalidVolume.NotFound message: {message!r}"
    )

    # 6. the Retain sibling is untouched: still present, still 'available', still tagged
    kept = ec2.describe_volumes(VolumeIds=[keep_vol])["Volumes"]
    assert [(v["VolumeId"], v["State"]) for v in kept] == [(keep_vol, "available")], (
        f"the Retain-policy volume {keep_vol} is {[(v['VolumeId'], v['State']) for v in kept]!r} "
        f"after delete-stack, expected it to survive in 'available'"
    )
    kept_tags = {t["Key"]: t["Value"] for t in kept[0].get("Tags", [])}
    assert kept_tags.get("role") == "keep", (
        f"the retained volume's tags are {kept_tags!r}; Retain must leave the resource as created"
    )

    # 7. Retain takes no snapshot -- the snapshot in (4) is the Snapshot policy's, not delete's
    assert _snapshots_of(ec2, keep_vol) == [], (
        f"a snapshot exists of the Retain-policy volume {keep_vol}: "
        f"{[s['SnapshotId'] for s in _snapshots_of(ec2, keep_vol)]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
