"""publish-of-empty-app-template-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-of-empty-app-template-rejected"
GROUP = 'app-versions'
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
    every other ConflictException is a real result and is re-raised untouched — which is what
    makes the rejection this check asserts readable rather than retried away.
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
    """PublishAppVersion on a draft with no mapped resources is refused with ConflictException
    ("Invalid app template. App template must have at least 1 resource") and creates no version; the
    same call succeeds once one resource is mapped and resolved, and `release` is then listed.
    """
    rh = ctx.client("resiliencehub")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    app_name = ctx.unique_name("sim2real-behav-rh-empty-")
    app_arn = rh.create_app(name=app_name)["app"]["appArn"]
    ctx.on_cleanup(lambda: _gone(
        lambda: rh.delete_app(appArn=app_arn, forceDelete=True), "ResourceNotFoundException"))

    # The one broken thing: nothing has been mapped into the draft.
    err = {}
    code = _error_code(lambda: rh.publish_app_version(appArn=app_arn, versionName="v1"), err)
    assert code == "ConflictException", (
        f"publishing an empty draft returned {code!r}, expected ConflictException "
        f"({err.get('Message')!r})")
    assert err.get("Message") == "Invalid app template. App template must have at least 1 resource", (
        f"the rejection does not carry the empty-template message: {err.get('Message')!r}")

    versions = {v["appVersion"] for v in _pages(
        rh.list_app_versions, "appVersions", appArn=app_arn)}
    assert versions == {"draft"}, (
        f"the rejected publish still produced a version: app carries {sorted(versions)!r}, "
        "expected only the draft")

    # Positive control: the same publish, with exactly one resource mapped, is accepted.
    bucket = ctx.unique_name("sim2real-behav-rh-empty-b-")
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

    published = _serialized(lambda: rh.publish_app_version(appArn=app_arn, versionName="v1"))
    assert published["appVersion"] == "release", (
        f"publish put the app template at {published['appVersion']!r}, expected 'release'")
    after = {v["appVersion"] for v in _pages(
        rh.list_app_versions, "appVersions", appArn=app_arn)}
    assert "release" in after, (
        f"the accepted publish left no release version: app carries {sorted(after)!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
