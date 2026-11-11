"""delete-application-while-associated-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-application-while-associated-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteApplication is rejected with ValidationException ('has an active association with
    stream group', not ConflictException) while the application is associated with a stream
    group, leaving it intact; after disassociating, the delete succeeds."""
    gl = ctx.client("gameliftstreams")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-glsbkt-")
    try:
        if ctx.region == "us-east-1":
            # us-east-1 is the one region where S3 CreateBucket rejects an explicit
            # LocationConstraint; every other region requires it.
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
        ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
        s3.put_object(Bucket=bucket, Key="build/start.sh", Body=b"#!/bin/sh\necho hi\n")
        ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="build/start.sh"))
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision a real associated application before spending GPU quota"
        )

    # Positive control: DeleteApplication succeeds on a healthy, never-associated application,
    # so the negative below cannot pass merely because DeleteApplication rejects everything.
    control_app_arn = gl.create_application(
        Description=ctx.unique_name("sim2real-behav-gls-ctrl-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="start.sh",
        ApplicationSourceUri=f"s3://{bucket}/build",
    )["Arn"]
    ctx.on_cleanup(lambda: _delete_application_when_settled(gl, control_app_arn))
    # DeleteApplication rejects an application that has not yet finished processing content
    # (ValidationException: "not in READY or ERROR status"), so the control must wait too.
    control_final = _poll_until(
        lambda: gl.get_application(Identifier=control_app_arn),
        lambda a: a["Status"] in ("READY", "ERROR"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert control_final["Status"] == "READY", (
        f"control application ended in {control_final['Status']}: "
        f"{control_final.get('StatusReason')}"
    )
    gl.delete_application(Identifier=control_app_arn)

    app = gl.create_application(
        Description=ctx.unique_name("sim2real-behav-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="start.sh",
        ApplicationSourceUri=f"s3://{bucket}/build",
    )
    app_arn = app["Arn"]
    ctx.on_cleanup(lambda: _delete_application_when_settled(gl, app_arn))
    app_final = _poll_until(
        lambda: gl.get_application(Identifier=app_arn),
        lambda a: a["Status"] in ("READY", "ERROR"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert app_final["Status"] == "READY", (
        f"application ended in {app_final['Status']}: {app_final.get('StatusReason')}"
    )

    try:
        sg = gl.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"),
            StreamClass="gen4n_high",
            LocationConfigurations=[{"LocationName": ctx.region, "MaximumCapacity": 2}],
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no Gen4n GPU quota in this Region ({e}); GameLift Streams GPU "
                "quotas default to 0 and must be explicitly requested"
            )
        raise
    sg_arn = sg["Arn"]
    ctx.on_cleanup(lambda: _delete_stream_group_when_settled(gl, sg_arn))
    sg_final = _poll_until(
        lambda: gl.get_stream_group(Identifier=sg_arn),
        lambda r: r["Status"] not in ("ACTIVATING", "UPDATING_LOCATIONS"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert sg_final["Status"] == "ACTIVE", (
        f"expected the stream group to reach ACTIVE, got {sg_final['Status']} "
        f"({sg_final.get('StatusReason')})"
    )

    gl.associate_applications(Identifier=sg_arn, ApplicationIdentifiers=[app_arn])
    ctx.on_cleanup(lambda: _disassociate_if_present(gl, sg_arn, app_arn))

    code, err_msg = _error_code(lambda: gl.delete_application(Identifier=app_arn))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {err_msg}"
    # AWS's message carries no closing quote after the stream group ARN.
    expected = f"Application '{app_arn}' has an active association with stream group '{sg_arn}"
    assert _without_internal_id(err_msg) == expected, f"expected {expected!r}, got {err_msg!r}"

    # Effect absent: the application still exists and is untouched.
    still_there = gl.get_application(Identifier=app_arn)
    assert still_there["Status"] != "DELETING", (
        f"rejected DeleteApplication must leave the application alone, got status "
        f"{still_there['Status']!r}"
    )

    # Positive control: clearing the association allows the delete to succeed.
    gl.disassociate_applications(Identifier=sg_arn, ApplicationIdentifiers=[app_arn])
    gl.delete_application(Identifier=app_arn)

    deadline = time.monotonic() + 180.0
    final_code, final_msg = None, None
    while time.monotonic() < deadline:
        try:
            final_code = gl.get_application(Identifier=app_arn)["Status"]
        except ClientError as e:
            final_code = e.response["Error"]["Code"]
            final_msg = e.response["Error"].get("Message", "")
            if final_code == "ResourceNotFoundException":
                break
        time.sleep(5.0)
    assert final_code == "ResourceNotFoundException", (
        f"expected the deleted application to read back ResourceNotFoundException within "
        f"180s, got {final_code!r}"
    )
    expected = f"Resource '{app_arn}' does not exist"
    assert _without_internal_id(final_msg) == expected, f"expected {expected!r}, got {final_msg!r}"


# ===== helpers =====
def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _without_internal_id(message):
    """GameLift Streams ends every error message with a per-request "(Internal ID: <uuid>)"."""
    stable, sep, rest = message.rpartition(" (Internal ID: ")
    assert sep and rest.endswith(")"), f"expected a trailing '(Internal ID: ...)', got {message!r}"
    return stable

def _delete_stream_group_when_settled(gls, arn, timeout_s=1800.0, interval_s=15.0):
    """DeleteStreamGroup refuses a group that is still ACTIVATING, so retry until it is
    accepted, then wait until the group is gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            gls.delete_stream_group(Identifier=arn)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while True:
        try:
            gls.get_stream_group(Identifier=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"stream group {arn} still present after {timeout_s}s")
        time.sleep(interval_s)

def _delete_application_when_settled(gls, arn, timeout_s=900.0, interval_s=10.0):
    """DeleteApplication refuses an application that is still processing or still associated
    with a stream group that is being deleted, so retry until it is accepted or already gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            gls.delete_application(Identifier=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)

def _disassociate_if_present(gls, sg_arn, app_arn):
    from botocore.exceptions import ClientError

    try:
        gls.disassociate_applications(Identifier=sg_arn, ApplicationIdentifiers=[app_arn])
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
