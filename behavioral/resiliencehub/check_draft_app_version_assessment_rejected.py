"""draft-app-version-assessment-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "draft-app-version-assessment-rejected"
GROUP = 'rejection'
SERVICES = ['resiliencehub']

_STORAGE = 'AWS::ResilienceHub::StorageAppComponent'
_TERMINAL = ('Success', 'Failed')
_ERR_VALIDATION = 'ValidationException'


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """StartAppAssessment on appVersion `draft` is refused with ValidationException ("AppAssessment
    version draft is invalid, must be release") and leaves no assessment, while the same call on
    `release` is accepted, pins the numbered version and runs to Success.
    """
    rh = ctx.client("resiliencehub")
    s3 = ctx.client("s3")

    policy_arn = rh.create_resiliency_policy(
        policyName=ctx.unique_name("sim2real-behav-rh-pol-"),
        tier="NonCritical",
        policy={
            "Software": {"rtoInSecs": 600, "rpoInSecs": 300},
            "Hardware": {"rtoInSecs": 600, "rpoInSecs": 300},
            "AZ": {"rtoInSecs": 600, "rpoInSecs": 300},
        },
    )["policy"]["policyArn"]
    ctx.on_cleanup(lambda: _delete_policy_when_released(ctx, policy_arn))

    app_arn = rh.create_app(
        name=ctx.unique_name("sim2real-behav-rh-app-"), policyArn=policy_arn
    )["app"]["appArn"]
    ctx.on_cleanup(lambda: rh.delete_app(appArn=app_arn, forceDelete=True))

    bucket = ctx.unique_name("sim2real-behav-rh-draft-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    component = "sim2real-behav-rh-store"
    rh.create_app_version_app_component(appArn=app_arn, name=component, type=_STORAGE)
    rh.create_app_version_resource(
        appArn=app_arn,
        resourceName="sim2real-behav-rh-bucket",
        logicalResourceId={"identifier": bucket},
        physicalResourceId=bucket,
        resourceType="AWS::S3::Bucket",
        appComponents=[component],
    )
    published = rh.publish_app_version(appArn=app_arn)
    assert published["appVersion"] == "release", (
        "publishing the draft did not produce a 'release' version, so the positive control below "
        "would be untestable"
    )
    numbered = str(published["identifier"])

    try:
        started = rh.start_app_assessment(
            appArn=app_arn,
            appVersion="draft",
            assessmentName=ctx.unique_name("sim2real-behav-rh-draftas-"),
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
        assert code == _ERR_VALIDATION, (
            f"assessing the draft failed with {code!r}, expected {_ERR_VALIDATION!r}. "
            f"message={message!r}"
        )
        expected_message = "AppAssessment version draft is invalid, must be release"
        assert message == expected_message, (
            f"the refusal message {message!r} is not AWS's unpublished-version refusal "
            f"{expected_message!r}"
        )
    else:
        raise AssertionError(
            "StartAppAssessment accepted appVersion='draft' and returned "
            f"{started['assessment']['assessmentArn']!r}; real AWS refuses it with "
            f"{_ERR_VALIDATION} because only a published version can be assessed"
        )

    orphans = rh.list_app_assessments(appArn=app_arn)["assessmentSummaries"]
    assert orphans == [], (
        f"the refused draft assessment still left {len(orphans)} assessment(s) on the app "
        f"({[a.get('assessmentArn') for a in orphans]}); a rejected start must queue no work"
    )

    # Positive control: the identical call against the published version.
    control = rh.start_app_assessment(
        appArn=app_arn,
        appVersion="release",
        assessmentName=ctx.unique_name("sim2real-behav-rh-relas-"),
    )["assessment"]
    assessment_arn = control["assessmentArn"]
    ctx.on_cleanup(lambda: rh.delete_app_assessment(assessmentArn=assessment_arn))
    assert control["appVersion"] == numbered, (
        f"the accepted assessment records appVersion {control['appVersion']!r}, expected the "
        f"numbered version {numbered!r} that the 'release' alias resolved to -- an assessment must "
        "pin the concrete version it graded, not the moving alias"
    )

    final = _await_assessment(ctx, assessment_arn)
    assert final["assessmentStatus"] == "Success", (
        f"the release assessment ended in {final['assessmentStatus']!r}, expected 'Success' -- the "
        "positive control must actually produce a verdict, not merely be accepted. "
        f"statusChangeReason={final.get('statusChangeReason')!r}"
    )
    assert final["complianceStatus"] in ("PolicyMet", "PolicyBreached"), (
        f"the completed assessment carried complianceStatus {final['complianceStatus']!r}, which is "
        "neither PolicyMet nor PolicyBreached"
    )

    listed = {
        a["assessmentArn"] for a in rh.list_app_assessments(appArn=app_arn)["assessmentSummaries"]
    }
    assert listed == {assessment_arn}, (
        f"ListAppAssessments for this app returned {sorted(listed)}, expected exactly the one "
        f"assessment that was accepted ({assessment_arn}) and nothing from the refused call"
    )


def _delete_policy_when_released(ctx, policy_arn: str, timeout_s: float = 240.0,
                                interval_s: float = 8.0) -> None:
    """Teardown that waits out the app's reference to its resiliency policy.

    DeleteApp returns before that reference is released, so a policy delete issued straight after it
    is refused with ConflictException for up to a couple of minutes; the teardown retries that
    refusal. ResourceNotFoundException means the check's own body already deleted it.
    """
    rh = ctx.client("resiliencehub")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rh.delete_resiliency_policy(policyArn=policy_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _await_assessment(ctx, assessment_arn: str, timeout_s: float = 600.0, interval_s: float = 5.0):
    """Drive DescribeAppAssessment until the assessment leaves Pending/InProgress.

    An assessment is asynchronous -- Pending -> InProgress -> Success in roughly twenty seconds for
    a single-resource app -- so there is no synchronous response that carries the verdict.
    """
    rh = ctx.client("resiliencehub")
    deadline = time.monotonic() + timeout_s
    assessment = {"assessmentStatus": "Pending"}
    while time.monotonic() < deadline:
        assessment = rh.describe_app_assessment(assessmentArn=assessment_arn)["assessment"]
        if assessment["assessmentStatus"] in _TERMINAL:
            return assessment
        time.sleep(interval_s)
    raise AssertionError(
        f"assessment {assessment_arn} was still {assessment['assessmentStatus']!r} after "
        f"{timeout_s:.0f}s; expected it to reach one of {_TERMINAL}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
