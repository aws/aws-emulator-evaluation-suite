"""published-version-freezes-resource-mapping."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "published-version-freezes-resource-mapping"
GROUP = 'app-versions'
SERVICES = ['resiliencehub']

_LOCKED = "AppVersionModel is currently being modified"


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


def _template_identifiers(rh, app_arn, version):
    """The logical resource ids the named app version's template actually carries."""
    body = rh.describe_app_version_template(appArn=app_arn, appVersion=version)["appTemplateBody"]
    return sorted(r["logicalResourceId"]["identifier"] for r in json.loads(body)["resources"])


def _add_bucket(ctx, rh, s3, app_arn, bucket, component, account):
    """Create a bucket, give it its own AppComponent, and map it into the draft app version."""
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _gone(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    _serialized(lambda: rh.create_app_version_app_component(
        appArn=app_arn, name=component, id=component,
        type="AWS::ResilienceHub::StorageAppComponent"))
    _serialized(lambda: rh.create_app_version_resource(
        appArn=app_arn, appComponents=[component], resourceType="AWS::S3::Bucket",
        logicalResourceId={"identifier": bucket}, physicalResourceId=bucket,
        resourceName=bucket, awsRegion=ctx.region, awsAccountId=account))


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PublishAppVersion snapshots the draft's mapping: the release template keeps exactly the
    resource it was published with while the draft gains a second, and after a republish the
    superseded version is still listed under its numeric appVersion with its original template.
    """
    rh = ctx.client("resiliencehub")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    app_name = ctx.unique_name("sim2real-behav-rh-freeze-")
    app_arn = rh.create_app(name=app_name)["app"]["appArn"]
    ctx.on_cleanup(lambda: _gone(
        lambda: rh.delete_app(appArn=app_arn, forceDelete=True), "ResourceNotFoundException"))

    first = ctx.unique_name("sim2real-behav-rh-frz-a-")
    _add_bucket(ctx, rh, s3, app_arn, first, "sim2real-behav-store-a", account)
    _resolve_draft(rh, app_arn)

    v1 = _serialized(lambda: rh.publish_app_version(appArn=app_arn, versionName="v1"))
    assert v1["appVersion"] == "release", (
        f"publish put the app template at {v1['appVersion']!r}, expected 'release'")
    v1_version = str(v1["identifier"])
    assert _template_identifiers(rh, app_arn, "release") == [first], (
        f"release template after v1 carries {_template_identifiers(rh, app_arn, 'release')!r}, "
        f"expected [{first!r}]")

    # Break the draft away from the release: a second bucket, its own component, re-resolved.
    second = ctx.unique_name("sim2real-behav-rh-frz-b-")
    _add_bucket(ctx, rh, s3, app_arn, second, "sim2real-behav-store-b", account)
    _resolve_draft(rh, app_arn)

    draft_ids = _template_identifiers(rh, app_arn, "draft")
    assert draft_ids == sorted([first, second]), (
        f"draft template carries {draft_ids!r}, expected {sorted([first, second])!r}")
    frozen = _template_identifiers(rh, app_arn, "release")
    assert frozen == [first], (
        f"the published release template followed the draft: it carries {frozen!r}, "
        f"expected the frozen [{first!r}]")

    v2 = _serialized(lambda: rh.publish_app_version(appArn=app_arn, versionName="v2"))
    assert str(v2["identifier"]) != v1_version, (
        f"second publish reused identifier {v2['identifier']!r} from the first")
    released = _template_identifiers(rh, app_arn, "release")
    assert released == sorted([first, second]), (
        f"release template after v2 carries {released!r}, expected {sorted([first, second])!r}")
    superseded = _template_identifiers(rh, app_arn, v1_version)
    assert superseded == [first], (
        f"superseded version {v1_version!r} carries {superseded!r}, "
        f"expected the frozen [{first!r}]")

    versions = {v["appVersion"]: v for v in _pages(
        rh.list_app_versions, "appVersions", appArn=app_arn)}
    assert set(versions) == {"draft", "release", v1_version}, (
        f"expected versions draft/release/{v1_version!r}, got {sorted(versions)!r}")
    assert versions[v1_version].get("versionName") == "v1", (
        f"version {v1_version!r} is named {versions[v1_version].get('versionName')!r}, "
        "expected 'v1'")
    assert versions["release"].get("versionName") == "v2", (
        f"release is named {versions['release'].get('versionName')!r}, expected 'v2'")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
