"""assessment-produces-policy-compliance-verdict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assessment-produces-policy-compliance-verdict"
GROUP = 'assessment'
SERVICES = ['resiliencehub']

_STORAGE = 'AWS::ResilienceHub::StorageAppComponent'
_TERMINAL = ('Success', 'Failed')
# The single policy threshold this check reasons about. 2592000s (30 days) is the largest RPO/RTO
# any resiliency policy will accept -- CreateResiliencyPolicy rejects 2592001 -- so a policy pinned
# at the ceiling is the most permissive one expressible, and any disruption the service still
# reports as breached is breached on the service's own measurement, not on a threshold we chose.
_CEILING_SECS = 2592000


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An assessment's verdict matches its numbers: each disruption is PolicyMet exactly when its
    RTO and RPO meet the policy, the rollup is breached exactly when one is, the score is in (0,
    100], and DescribeApp then carries the same verdict and score.
    """
    rh = ctx.client("resiliencehub")
    s3 = ctx.client("s3")

    thresholds = {
        d: {"rtoInSecs": _CEILING_SECS, "rpoInSecs": _CEILING_SECS}
        for d in ("Software", "Hardware", "AZ")
    }
    policy_arn = rh.create_resiliency_policy(
        policyName=ctx.unique_name("sim2real-behav-rh-pol-"),
        tier="NonCritical",
        policy=thresholds,
    )["policy"]["policyArn"]
    ctx.on_cleanup(lambda: _delete_policy_when_released(ctx, policy_arn))

    app_arn = rh.create_app(
        name=ctx.unique_name("sim2real-behav-rh-app-"), policyArn=policy_arn
    )["app"]["appArn"]
    ctx.on_cleanup(lambda: rh.delete_app(appArn=app_arn, forceDelete=True))

    bucket = ctx.unique_name("sim2real-behav-rh-assess-")
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
    assert rh.publish_app_version(appArn=app_arn)["appVersion"] == "release", (
        "publishing the draft did not produce a 'release' version, so there is nothing to assess"
    )

    started = rh.start_app_assessment(
        appArn=app_arn,
        appVersion="release",
        assessmentName=ctx.unique_name("sim2real-behav-rh-as-"),
    )["assessment"]
    assessment_arn = started["assessmentArn"]
    ctx.on_cleanup(lambda: rh.delete_app_assessment(assessmentArn=assessment_arn))
    assert started["assessmentStatus"] in ("Pending", "InProgress"), (
        f"a freshly started assessment reported status {started['assessmentStatus']!r}; expected "
        "it to begin in Pending or InProgress"
    )

    assessment = _await_assessment(ctx, assessment_arn)
    assert assessment["assessmentStatus"] == "Success", (
        f"the assessment ended in {assessment['assessmentStatus']!r}, expected 'Success'. "
        f"statusChangeReason={assessment.get('statusChangeReason')!r}"
    )

    echoed = assessment["policy"]["policy"]
    for disruption, want in thresholds.items():
        assert disruption in echoed, (
            f"the assessment's echoed policy dropped disruption {disruption!r}; it carried "
            f"{sorted(echoed)}"
        )
        assert echoed[disruption]["rtoInSecs"] == want["rtoInSecs"], (
            f"the assessment echoed an rtoInSecs of {echoed[disruption]['rtoInSecs']} for "
            f"{disruption}, but the policy it assessed against says {want['rtoInSecs']}"
        )

    compliance = assessment["compliance"]
    assert set(thresholds) <= set(compliance), (
        f"the verdict covered disruptions {sorted(compliance)}, which omits some of the policy's "
        f"{sorted(thresholds)} -- every disruption the policy constrains must get a verdict"
    )

    breached = []
    for disruption, want in thresholds.items():
        verdict = compliance[disruption]
        status = verdict["complianceStatus"]
        assert status in ("PolicyMet", "PolicyBreached"), (
            f"{disruption} carried complianceStatus {status!r}, which is neither PolicyMet nor "
            "PolicyBreached"
        )
        rto = verdict.get("currentRtoInSecs")
        rpo = verdict.get("currentRpoInSecs")
        assert isinstance(rto, int) and isinstance(rpo, int), (
            f"{disruption} reported a verdict with currentRtoInSecs={rto!r} and "
            f"currentRpoInSecs={rpo!r}; a completed assessment must measure both as integers"
        )
        within = rto <= want["rtoInSecs"] and rpo <= want["rpoInSecs"]
        expected = "PolicyMet" if within else "PolicyBreached"
        assert status == expected, (
            f"{disruption} is internally inconsistent: measured RTO {rto}s / RPO {rpo}s against "
            f"thresholds RTO {want['rtoInSecs']}s / RPO {want['rpoInSecs']}s, which is "
            f"{expected}, but the verdict says {status}"
        )
        if status == "PolicyBreached":
            breached.append(disruption)

    rollup = assessment["complianceStatus"]
    expected_rollup = "PolicyBreached" if breached else "PolicyMet"
    assert rollup == expected_rollup, (
        f"the roll-up complianceStatus is {rollup!r} while the per-disruption verdicts breached "
        f"{sorted(breached) or 'nothing'}; the roll-up must be {expected_rollup!r}"
    )

    score = assessment["resiliencyScore"]
    assert 0.0 < score["score"] <= 100.0, (
        f"the assessment scored {score['score']!r}; a completed assessment of a mapped app must "
        "produce a positive score"
    )
    assert set(thresholds) <= set(score["disruptionScore"]), (
        f"the score broke down by disruption as {sorted(score['disruptionScore'])}, which omits "
        f"some of the policy's {sorted(thresholds)}"
    )

    # The verdict must land back on the app resource, which no response envelope can show.
    app = rh.describe_app(appArn=app_arn)["app"]
    assert app["complianceStatus"] == rollup, (
        f"DescribeApp reports complianceStatus {app['complianceStatus']!r} after a completed "
        f"assessment whose roll-up was {rollup!r}; the verdict must propagate onto the app"
    )
    assert app["resiliencyScore"] == score["score"], (
        f"DescribeApp reports resiliencyScore {app['resiliencyScore']!r} but the assessment "
        f"scored {score['score']!r}"
    )
    assert app["lastAppComplianceEvaluationTime"], (
        "DescribeApp carried no lastAppComplianceEvaluationTime after a completed assessment"
    )

    listed = {
        s["assessmentArn"]
        for s in rh.list_app_assessments(appArn=app_arn)["assessmentSummaries"]
    }
    assert listed == {assessment_arn}, (
        f"ListAppAssessments for this app returned {sorted(listed)}, expected exactly the one "
        f"assessment this check started ({assessment_arn})"
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
