"""associate-applications-nonexistent-app-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-applications-nonexistent-app-not-found"
GROUP = "error-semantics"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateApplications with an application identifier that does not exist fails with ResourceNotFoundException
    and its message and leaves the ACTIVE stream group without associations, while a READY application
    associates.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    gl = ctx.client("gameliftstreams")
    sg_arn = _create_active_stream_group(ctx, gl, teardown_deadline)

    bogus_app = ctx.unique_name("a-")
    code, message = _error_code(
        lambda: gl.associate_applications(Identifier=sg_arn, ApplicationIdentifiers=[bogus_app])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    bogus_arn = sg_arn.split(":streamgroup/")[0] + f":application/{bogus_app}"
    expected = f"Resource '{bogus_arn}' does not exist"
    assert _without_internal_id(message) == expected, f"expected {expected!r}, got {message!r}"

    before = gl.get_stream_group(Identifier=sg_arn)["AssociatedApplications"]
    assert before == [], f"expected no associations after the rejected AssociateApplications, got {before!r}"

    # Positive control (needs S3 write access to provision real application content): a real
    # application on the same ACTIVE group associates successfully.
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-glsbkt-")
    try:
        if ctx.region == "us-east-1":
            # S3 rejects an explicit LocationConstraint for the us-east-1 region.
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot provision "
            "real application content for the positive control"
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "build/start.sh"
    s3.put_object(Bucket=bucket, Key=key, Body=b"#!/bin/sh\necho hi\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    app = gl.create_application(
        Description=ctx.unique_name("sim2real-behav-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="start.sh",
        ApplicationSourceUri=f"s3://{bucket}/build",
        Tags={"sim2real-check": CHECK},
    )
    app_arn = app["Arn"]
    ctx.on_cleanup(lambda: _delete_application_when_settled(gl, app_arn, teardown_deadline))
    _wait_application_ready(ctx, gl, app_arn)

    gl.associate_applications(Identifier=sg_arn, ApplicationIdentifiers=[app_arn])
    ctx.on_cleanup(lambda: _disassociate_if_present(gl, sg_arn, app_arn))
    after = gl.get_stream_group(Identifier=sg_arn)["AssociatedApplications"]
    assert app_arn in after, f"expected {app_arn!r} in AssociatedApplications after a successful AssociateApplications, got {after!r}"


def _create_active_stream_group(ctx, gl, teardown_deadline, timeout_s=900.0, interval_s=10.0):
    try:
        created = gl.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"),
            StreamClass="gen4n_high",
            LocationConfigurations=[{"LocationName": ctx.region, "MaximumCapacity": 2}],
            Tags={"sim2real-check": CHECK},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(f"account has no StreamGroup capacity quota in this Region ({e})")
        raise
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_stream_group_when_settled(gl, arn, teardown_deadline))

    deadline = time.monotonic() + timeout_s
    last = created
    while last["Status"] in ("ACTIVATING", "UPDATING_LOCATIONS"):
        if time.monotonic() >= deadline:
            raise AssertionError(f"stream group did not reach ACTIVE within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = gl.get_stream_group(Identifier=arn)
    assert last["Status"] == "ACTIVE", f"expected ACTIVE, got {last['Status']} ({last.get('StatusReason')})"
    return arn


def _wait_application_ready(ctx, gl, app_arn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = gl.get_application(Identifier=app_arn)
    while last["Status"] not in ("READY", "ERROR"):
        if time.monotonic() >= deadline:
            raise AssertionError(f"application did not reach READY within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = gl.get_application(Identifier=app_arn)
    assert last["Status"] == "READY", f"expected READY, got {last['Status']} ({last.get('StatusReason')})"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _without_internal_id(message):
    """GameLift Streams ends every error message with a per-request "(Internal ID: <uuid>)"."""
    stable, sep, rest = message.rpartition(" (Internal ID: ")
    assert sep and rest.endswith(")"), f"expected a trailing '(Internal ID: ...)', got {message!r}"
    return stable


# The suite's 900 s teardown budget: one deadline shared by every teardown of a run.
_TEARDOWN_S = 900.0


def _teardown_deadline(teardown_deadline):
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_S - 120.0)


def _delete_stream_group_when_settled(gls, arn, teardown_deadline, interval_s=2.0):
    """DeleteStreamGroup refuses a group that is still ACTIVATING, so retry until it is
    accepted, then wait until the group is gone, to the shared teardown deadline."""
    from botocore.exceptions import ClientError

    deadline = _teardown_deadline(teardown_deadline)
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
            raise AssertionError(f"stream group {arn} still present at the teardown deadline")
        time.sleep(interval_s)

def _delete_application_when_settled(gls, arn, teardown_deadline, interval_s=2.0):
    """DeleteApplication refuses an application that is still processing or still associated
    with a stream group that is being deleted, so retry until it is accepted or already gone."""
    from botocore.exceptions import ClientError

    deadline = _teardown_deadline(teardown_deadline)
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
