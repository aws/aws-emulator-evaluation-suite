"""associate-applications-bidirectional-link."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-applications-bidirectional-link"
GROUP = "state"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateApplications links a READY application to an ACTIVE stream group: both sides list the link,
    and the group's DefaultApplication becomes that application.
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    s3 = ctx.client("s3")
    gls = ctx.client("gameliftstreams")

    app = _create_ready_application(ctx, gls, s3, teardown_deadline)
    group = _create_active_stream_group(ctx, gls)

    resp = gls.associate_applications(
        Identifier=group["Arn"], ApplicationIdentifiers=[app["Id"]]
    )
    assert app["Arn"] in resp["ApplicationArns"], (
        f"expected {app['Arn']} in AssociateApplications' own ApplicationArns, "
        f"got {resp['ApplicationArns']!r}"
    )

    reread_group = gls.get_stream_group(Identifier=group["Arn"])
    assert app["Arn"] in reread_group["AssociatedApplications"], (
        f"expected {app['Arn']} in GetStreamGroup.AssociatedApplications, "
        f"got {reread_group['AssociatedApplications']!r}"
    )
    assert reread_group["DefaultApplication"]["Arn"] == app["Arn"], (
        f"expected the first associated application {app['Arn']} to be auto-assigned as "
        f"DefaultApplication, got {reread_group.get('DefaultApplication')!r}"
    )

    reread_app = gls.get_application(Identifier=app["Id"])
    assert group["Arn"] in reread_app["AssociatedStreamGroups"], (
        f"expected {group['Arn']} in GetApplication.AssociatedStreamGroups, "
        f"got {reread_app['AssociatedStreamGroups']!r}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _create_bucket(ctx, s3, suffix="app"):
    from botocore.exceptions import ClientError


    bucket = ctx.unique_name(f"sim2real-behav-gls-{suffix}-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision real application content"
        )

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_ready_application(ctx, gls, s3, teardown_deadline, script_body=b"#!/bin/sh\nexit 0\n", timeout_s=600.0):
    bucket = _create_bucket(ctx, s3, suffix="app")
    s3.put_object(Bucket=bucket, Key="app/run.sh", Body=script_body)
    app = gls.create_application(
        Description=ctx.unique_name("sim2real-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="run.sh",
        ApplicationSourceUri=f"s3://{bucket}/app/",
        Tags={"sim2real-audit": "associate-applications-bidirectional-link"},
    )
    app_id = app["Id"]
    ctx.on_cleanup(lambda: _delete_application_when_settled(gls, app_id, teardown_deadline))
    final = _poll_until(
        lambda: gls.get_application(Identifier=app_id),
        lambda a: a["Status"] in ("READY", "ERROR"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    if final["Status"] != "READY":
        raise AssertionError(f"application did not reach READY: {final.get('StatusReason')}")
    return final


def _create_active_stream_group(ctx, gls, location_configurations=None, timeout_s=300.0):
    from botocore.exceptions import ClientError

    kwargs = {
        "Description": ctx.unique_name("sim2real-gls-sg-"),
        "StreamClass": "gen6n_small",
        "Tags": {"sim2real-audit": "associate-applications-bidirectional-link"},
    }
    if location_configurations:
        kwargs["LocationConfigurations"] = location_configurations
    try:
        group = gls.create_stream_group(**kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no GPU quota in this Region ({e}); GameLift Streams GPU quotas "
                "default to 0 and must be explicitly requested"
            )
        raise
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: gls.delete_stream_group(Identifier=arn)))
    final = _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        lambda g: g["Status"] in ("ACTIVE", "ACTIVE_WITH_ERRORS", "ERROR"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    if final["Status"] != "ACTIVE":
        raise AssertionError(
            f"stream group did not reach ACTIVE: {final['Status']}/{final.get('StatusReason')}"
        )
    return final


# The suite's 900 s teardown budget: one deadline shared by every teardown of a run.
_TEARDOWN_S = 900.0


def _teardown_deadline(teardown_deadline):
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_S - 120.0)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
