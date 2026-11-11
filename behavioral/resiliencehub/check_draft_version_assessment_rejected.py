"""draft-version-assessment-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "draft-version-assessment-rejected"
GROUP = 'assessments'
SERVICES = ['resiliencehub']

_LOCKED = "AppVersionModel is currently being modified"


class _UnexpectedSuccess(Exception):
    """A call real AWS rejects returned successfully."""


def _error_code(fn, seen=None):
    """Call fn(); return the Error.Code of the ClientError it must raise.

    An unexpected success raises rather than returning a falsy sentinel: an emulator accepting
    input real AWS rejects is the strongest signal available and must not read as a code mismatch.
    When `seen` is a dict it receives the whole Error entry, so the message can be asserted
    without firing the call twice.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if seen is not None:
            seen.update(err)
        return err.get("Code")
    raise _UnexpectedSuccess(f"expected a rejection, got a successful response: {result!r}")


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


def _pages(fn, key, **kw):
    """Every page of a nextToken list, so a match past the first page is not missed."""
    items, token = [], None
    while True:
        page = fn(nextToken=token, **kw) if token else fn(**kw)
        items.extend(page.get(key, []))
        token = page.get("nextToken")
        if not token:
            return items


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartAppAssessment on a resolved `draft` is refused with ValidationException ("AppAssessment
    version draft is invalid, must be release") and creates nothing; after a publish the same call
    on `release` is accepted, pinned to the numbered version v1.
    """
    rh = ctx.client("resiliencehub")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    policy_name = ctx.unique_name("sim2real-behav-rh-drf-pol-")
    policy_arn = rh.create_resiliency_policy(
        policyName=policy_name, tier="CoreServices",
        policy={d: {"rtoInSecs": 60, "rpoInSecs": 86400}
                for d in ("AZ", "Hardware", "Software", "Region")})["policy"]["policyArn"]
    ctx.on_cleanup(lambda: _gone(
        lambda: rh.delete_resiliency_policy(policyArn=policy_arn), "ResourceNotFoundException"))

    app_name = ctx.unique_name("sim2real-behav-rh-draft-")
    app_arn = rh.create_app(name=app_name, policyArn=policy_arn)["app"]["appArn"]
    ctx.on_cleanup(lambda: _gone(
        lambda: rh.delete_app(appArn=app_arn, forceDelete=True), "ResourceNotFoundException"))

    bucket = ctx.unique_name("sim2real-behav-rh-draft-b-")
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

    # The one broken thing: a fully resolved draft is still not an assessable version.
    rejected_name = ctx.unique_name("sim2real-behav-rh-draft-asmt-")
    err = {}
    code = _error_code(lambda: rh.start_app_assessment(
        appArn=app_arn, appVersion="draft", assessmentName=rejected_name), err)
    assert code == "ValidationException", (
        f"assessing the draft returned {code!r}, expected ValidationException ({err.get('Message')!r})")
    assert err.get("Message") == "AppAssessment version draft is invalid, must be release", (
        f"the rejection does not carry the draft-version message: {err.get('Message')!r}")

    named = _pages(rh.list_app_assessments, "assessmentSummaries", appArn=app_arn)
    assert not named, (
        f"the rejected call still created an assessment: {[a.get('assessmentName') for a in named]!r}")

    # Positive control: the same call, on a published version, is accepted.
    published = _serialized(lambda: rh.publish_app_version(appArn=app_arn, versionName="v1"))
    assert published["appVersion"] == "release", (
        f"publish put the app template at {published['appVersion']!r}, expected 'release'")
    accepted_name = ctx.unique_name("sim2real-behav-rh-rel-asmt-")
    accepted = rh.start_app_assessment(
        appArn=app_arn, appVersion="release", assessmentName=accepted_name)["assessment"]
    # The accepted assessment is pinned to the concrete version the alias pointed at.
    assert accepted["appVersion"] == str(published["identifier"]), (
        f"accepted assessment names appVersion {accepted['appVersion']!r}, expected the published "
        f"version {str(published['identifier'])!r} that 'release' pointed at")
    assert accepted["versionName"] == "v1", (
        f"accepted assessment names versionName {accepted.get('versionName')!r}, expected 'v1'")
    listed = {a.get("assessmentName") for a in _pages(
        rh.list_app_assessments, "assessmentSummaries", appArn=app_arn)}
    assert listed == {accepted_name}, (
        f"expected exactly the accepted assessment {accepted_name!r} on this app, got {listed!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
