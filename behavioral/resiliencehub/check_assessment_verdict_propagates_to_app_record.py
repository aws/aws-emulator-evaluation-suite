"""assessment-verdict-propagates-to-app-record."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assessment-verdict-propagates-to-app-record"
GROUP = 'assessments'
SERVICES = ['resiliencehub']

_LOCKED = "AppVersionModel is currently being modified"
_RTO_SECS = 60
_RPO_SECS = 86400


def _gone(fn, *codes):
    """Run a teardown step, tolerating only the codes that mean it is already done."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _serialized(fn, attempts=25, delay=3.0):
    """Retry fn while the draft app version is locked by an in-flight mutation of its own.

    ResilienceHub serialises draft mutations behind a ConflictException that names the lock;
    every other ConflictException is a real result and is re-raised untouched.
    """
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "ConflictException" or _LOCKED not in err.get("Message", ""):
                raise
            last = err.get("Message")
            time.sleep(delay)
    raise AssertionError(f"draft still locked after {attempts} attempts: {last!r}")


def _resolve_draft(rh, app_arn, deadline=180.0):
    """Resolve the draft's resource mapping and poll the resolution to a terminal status."""
    rid = _serialized(
        lambda: rh.resolve_app_version_resources(appArn=app_arn, appVersion="draft")
    )["resolutionId"]
    status, end = None, time.time() + deadline
    while time.time() < end:
        status = rh.describe_app_version_resources_resolution_status(
            appArn=app_arn, appVersion="draft", resolutionId=rid)["status"]
        if status in ("Success", "Failed"):
            break
        time.sleep(3)
    assert status == "Success", (
        f"resolution {rid!r} ended {status!r} within {deadline}s, expected Success")
    return rid


def _await_assessment(rh, assessment_arn, deadline=200.0):
    """Poll the assessment to a terminal status; anything but Success is this check failing."""
    seen, end = {}, time.time() + deadline
    while time.time() < end:
        seen = rh.describe_app_assessment(assessmentArn=assessment_arn)["assessment"]
        if seen["assessmentStatus"] in ("Success", "Failed"):
            break
        time.sleep(5)
    assert seen.get("assessmentStatus") == "Success", (
        f"assessment {assessment_arn!r} was {seen.get('assessmentStatus')!r} after {deadline}s: "
        f"{seen.get('message')!r}")
    return seen


def _published_app_with_policy(ctx, rh, s3, account, label):
    """A one-bucket app, resolved and published, associated with a tight resiliency policy."""
    policy_name = ctx.unique_name(f"sim2real-behav-rh-{label}-pol-")
    targets = {d: {"rtoInSecs": _RTO_SECS, "rpoInSecs": _RPO_SECS}
               for d in ("AZ", "Hardware", "Software", "Region")}
    policy_arn = rh.create_resiliency_policy(
        policyName=policy_name, tier="CoreServices", policy=targets)["policy"]["policyArn"]
    ctx.on_cleanup(lambda: _gone(
        lambda: rh.delete_resiliency_policy(policyArn=policy_arn), "ResourceNotFoundException"))

    app_name = ctx.unique_name(f"sim2real-behav-rh-{label}-")
    app_arn = rh.create_app(name=app_name, policyArn=policy_arn)["app"]["appArn"]
    ctx.on_cleanup(lambda: _gone(
        lambda: rh.delete_app(appArn=app_arn, forceDelete=True), "ResourceNotFoundException"))

    bucket = ctx.unique_name(f"sim2real-behav-rh-{label}-b-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _gone(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))

    component = "sim2real-behav-store"
    _serialized(lambda: rh.create_app_version_app_component(
        appArn=app_arn, name=component, id=component,
        type="AWS::ResilienceHub::StorageAppComponent"))
    _serialized(lambda: rh.create_app_version_resource(
        appArn=app_arn, appComponents=[component], resourceType="AWS::S3::Bucket",
        logicalResourceId={"identifier": bucket}, physicalResourceId=bucket,
        resourceName=bucket, awsRegion=ctx.region, awsAccountId=account))
    _resolve_draft(rh, app_arn)
    _serialized(lambda: rh.publish_app_version(appArn=app_arn, versionName="v1"))
    return app_arn, policy_arn, targets


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A completed assessment writes its verdict onto the app record: DescribeApp reports
    NotAssessed with no evaluation time before, and afterwards the assessment's complianceStatus and
    resiliencyScore, stamped with the assessment's endTime.
    """
    rh = ctx.client("resiliencehub")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    app_arn, policy_arn, _ = _published_app_with_policy(ctx, rh, s3, account, "prop")

    before = rh.describe_app(appArn=app_arn)["app"]
    assert before["complianceStatus"] == "NotAssessed", (
        f"a never-assessed app reports complianceStatus {before['complianceStatus']!r}, "
        "expected 'NotAssessed'")
    assert "lastAppComplianceEvaluationTime" not in before, (
        "a never-assessed app already carries lastAppComplianceEvaluationTime "
        f"{before.get('lastAppComplianceEvaluationTime')!r}")
    assert before["policyArn"] == policy_arn, (
        f"app reports policyArn {before['policyArn']!r}, expected {policy_arn!r}")

    name = ctx.unique_name("sim2real-behav-rh-asmt-")
    assessment_arn = rh.start_app_assessment(
        appArn=app_arn, appVersion="release", assessmentName=name)["assessment"]["assessmentArn"]
    assessment = _await_assessment(rh, assessment_arn)

    after = rh.describe_app(appArn=app_arn)["app"]
    assert after["complianceStatus"] == assessment["complianceStatus"], (
        f"app records complianceStatus {after['complianceStatus']!r} but the assessment concluded "
        f"{assessment['complianceStatus']!r}")
    assert after["resiliencyScore"] == assessment["resiliencyScore"]["score"], (
        f"app records resiliencyScore {after['resiliencyScore']!r} but the assessment scored "
        f"{assessment['resiliencyScore']['score']!r}")
    assert after["lastAppComplianceEvaluationTime"] == assessment["endTime"], (
        f"app stamped lastAppComplianceEvaluationTime "
        f"{after['lastAppComplianceEvaluationTime']!r} but the assessment ended at "
        f"{assessment['endTime']!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
