"""workgroup-create-conflict-survives-settling-to-available."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workgroup-create-conflict-survives-settling-to-available"
GROUP = "lifecycle"
SERVICES = ["redshift-serverless"]


def expect_error(fn, code: str, message: str) -> None:
    """Assert fn() raises exactly this (code, message); raise on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert (err.get("Code"), err.get("Message")) == (code, message), err
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _poll_to_available(rss, workgroup_name: str, *, deadline_s: float = 900.0,
                       interval_s: float = 15.0) -> dict:
    """Poll GetWorkgroup until status AVAILABLE; raise once the deadline passes."""
    end = time.monotonic() + deadline_s
    while True:
        wg = rss.get_workgroup(workgroupName=workgroup_name)["workgroup"]
        if wg["status"] == "AVAILABLE":
            return wg
        if time.monotonic() >= end:
            raise AssertionError(
                f"workgroup {workgroup_name!r} still {wg['status']!r} after {deadline_s}s")
        time.sleep(interval_s)


def _delete_workgroup_and_wait(rss, workgroup_name: str, *, deadline_s: float = 900.0,
                               interval_s: float = 15.0) -> None:
    end = time.monotonic() + deadline_s
    while True:
        try:
            rss.delete_workgroup(workgroupName=workgroup_name)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            still_busy = (err["Code"], err.get("Message")) == (
                "ConflictException",
                "There is an operation running on the workgroup. Try to delete it later.",
            )
            if not still_busy or time.monotonic() >= end:
                raise
            time.sleep(interval_s)
    while time.monotonic() < end:
        try:
            rss.get_workgroup(workgroupName=workgroup_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"workgroup {workgroup_name!r} still present {deadline_s}s after delete")


def _delete_namespace_and_wait(rss, namespace_name: str, *, deadline_s: float = 900.0,
                               interval_s: float = 15.0) -> None:
    try:
        rss.delete_namespace(namespaceName=namespace_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        try:
            rss.get_namespace(namespaceName=namespace_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"namespace {namespace_name!r} still present {deadline_s}s after delete")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Once a workgroup is AVAILABLE, CreateWorkgroup reusing its name is refused and its id,
    ARN, capacity and endpoint stay as they were; a new name in the occupied namespace is refused
    as well, and that new name is accepted in an empty namespace."""
    rss = ctx.client("redshift-serverless")

    home_namespace = ctx.unique_name("sim2real-behav-rsns-")
    rss.create_namespace(namespaceName=home_namespace, dbName="dev")
    ctx.on_cleanup(lambda: _delete_namespace_and_wait(rss, home_namespace))

    resident_name = ctx.unique_name("sim2real-behav-rswg-")
    rss.create_workgroup(workgroupName=resident_name, namespaceName=home_namespace,
                        baseCapacity=8, publiclyAccessible=False)
    ctx.on_cleanup(lambda: _delete_workgroup_and_wait(rss, resident_name))

    settled = _poll_to_available(rss, resident_name)
    settled_fingerprint = (
        settled["workgroupId"],
        settled["workgroupArn"],
        settled["baseCapacity"],
        settled["endpoint"]["address"],
        settled["endpoint"]["port"],
    )

    _REPEAT_CREATE_CONFLICT = (
        "ConflictException",
        f"The workgroup with name {resident_name} already exists.",
    )
    expect_error(
        lambda: rss.create_workgroup(workgroupName=resident_name, namespaceName=home_namespace,
                                     baseCapacity=32, publiclyAccessible=False),
        *_REPEAT_CREATE_CONFLICT,
    )

    after_repeat = rss.get_workgroup(workgroupName=resident_name)["workgroup"]
    after_repeat_fingerprint = (
        after_repeat["workgroupId"],
        after_repeat["workgroupArn"],
        after_repeat["baseCapacity"],
        after_repeat["endpoint"]["address"],
        after_repeat["endpoint"]["port"],
    )
    assert after_repeat_fingerprint == settled_fingerprint, (
        f"the refused repeat create changed (id, arn, capacity, endpoint) from "
        f"{settled_fingerprint!r} to {after_repeat_fingerprint!r}")

    challenger_name = ctx.unique_name("sim2real-behav-rswg-")
    _NAMESPACE_OCCUPIED_CONFLICT = (
        "ConflictException",
        f"There is already a workgroup {resident_name} associated with the namespace.",
    )
    expect_error(
        lambda: rss.create_workgroup(workgroupName=challenger_name, namespaceName=home_namespace,
                                     baseCapacity=8, publiclyAccessible=False),
        *_NAMESPACE_OCCUPIED_CONFLICT,
    )

    spare_namespace = ctx.unique_name("sim2real-behav-rsns-")
    rss.create_namespace(namespaceName=spare_namespace, dbName="dev")
    ctx.on_cleanup(lambda: _delete_namespace_and_wait(rss, spare_namespace))

    rss.create_workgroup(workgroupName=challenger_name, namespaceName=spare_namespace,
                        baseCapacity=8, publiclyAccessible=False)
    ctx.on_cleanup(lambda: _delete_workgroup_and_wait(rss, challenger_name))

    relocated = rss.get_workgroup(workgroupName=challenger_name)["workgroup"]
    assert relocated["namespaceName"] == spare_namespace, (
        f"{challenger_name!r} landed in namespace {relocated['namespaceName']!r}, "
        f"expected the fresh namespace {spare_namespace!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
