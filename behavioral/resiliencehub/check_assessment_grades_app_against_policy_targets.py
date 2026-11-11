"""assessment-grades-app-against-policy-targets."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assessment-grades-app-against-policy-targets"
GROUP = 'assessments'
SERVICES = ['resiliencehub']

_LOCKED = "AppVersionModel is currently being modified"
# Tight enough that an unachievable disruption breaches: real AWS reports 2592001s (30 days + 1)
# for both RTO and RPO on a disruption the app cannot recover from, and 0 for one it can.
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
    """A one-bucket app, resolved and published, associated with a tight resiliency policy.

    Returns (app_arn, policy_arn, policy_targets, published_version). Cleanup is registered as
    each thing is created, and LIFO order tears the app down before the policy it references.
    """
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
    published = _serialized(lambda: rh.publish_app_version(appArn=app_arn, versionName="v1"))
    return app_arn, policy_arn, targets, str(published["identifier"])


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An assessment of a published app version grades it against its policy: each disruption is
    PolicyBreached exactly when its measured RTO or RPO exceeds the target, the rollup is breached
    exactly when one is, and the score is the per-disruption mean over a breakdown summing to 1.
    """
    rh = ctx.client("resiliencehub")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    app_arn, policy_arn, targets, version = _published_app_with_policy(
        ctx, rh, s3, account, "grade")

    name = ctx.unique_name("sim2real-behav-rh-asmt-")
    started = rh.start_app_assessment(
        appArn=app_arn, appVersion="release", assessmentName=name)["assessment"]
    assessment_arn = started["assessmentArn"]
    assessment = _await_assessment(rh, assessment_arn)

    assert assessment["policy"]["policyArn"] == policy_arn, (
        f"assessment graded against {assessment['policy']['policyArn']!r}, expected {policy_arn!r}")
    # The moving alias the request named is resolved to the concrete version it pointed at.
    assert assessment["appVersion"] == version, (
        f"assessment names appVersion {assessment['appVersion']!r}, expected the published "
        f"version {version!r} that 'release' pointed at")
    assert assessment["versionName"] == "v1", (
        f"assessment names versionName {assessment.get('versionName')!r}, expected 'v1'")

    compliance = assessment["compliance"]
    assert set(compliance) == set(targets), (
        f"assessment covers disruptions {sorted(compliance)!r}, expected {sorted(targets)!r}")

    breached = set()
    for disruption, observed in sorted(compliance.items()):
        target = targets[disruption]
        assert "currentRtoInSecs" in observed and "currentRpoInSecs" in observed, (
            f"{disruption} compliance reports no measured RTO/RPO: {observed!r}")
        over_target = (observed["currentRtoInSecs"] > target["rtoInSecs"]
                       or observed["currentRpoInSecs"] > target["rpoInSecs"])
        is_breach = observed["complianceStatus"] == "PolicyBreached"
        assert over_target == is_breach, (
            f"{disruption}: measured RTO/RPO "
            f"{observed['currentRtoInSecs']!r}/{observed['currentRpoInSecs']!r} against targets "
            f"{target['rtoInSecs']!r}/{target['rpoInSecs']!r} but complianceStatus is "
            f"{observed['complianceStatus']!r}")
        if is_breach:
            breached.add(disruption)

    expected_rollup = "PolicyBreached" if breached else "PolicyMet"
    assert assessment["complianceStatus"] == expected_rollup, (
        f"app-level complianceStatus is {assessment['complianceStatus']!r} while the breached "
        f"disruptions are {sorted(breached)!r}, expected {expected_rollup!r}")

    score = assessment["resiliencyScore"]
    per_disruption = score["disruptionScore"]
    assert set(per_disruption) == set(targets), (
        f"score covers disruptions {sorted(per_disruption)!r}, expected {sorted(targets)!r}")
    mean = sum(per_disruption.values()) / len(per_disruption)
    assert abs(score["score"] - mean) < 1e-6, (
        f"overall score {score['score']!r} is not the mean {mean!r} of {per_disruption!r}")
    components = score["componentScore"]
    possible = sum(c["possibleScore"] for c in components.values())
    assert abs(possible - 1.0) < 1e-6, (
        f"component possibleScore sums to {possible!r}, expected 1.0, over {components!r}")
    earned = sum(c["score"] for c in components.values())
    assert abs(earned - score["score"]) < 1e-6, (
        f"component scores sum to {earned!r} but the overall score is {score['score']!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
