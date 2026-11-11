"""app-without-mapped-resources-rejects-publish."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "app-without-mapped-resources-rejects-publish"
GROUP = 'rejection'
SERVICES = ['resiliencehub']

_STORAGE = 'AWS::ResilienceHub::StorageAppComponent'
_ERR_CONFLICT = 'ConflictException'


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """PublishAppVersion on an app whose draft maps no resources is refused with ConflictException
    "Invalid app template. App template must have at least 1 resource" and creates no release;
    after mapping one resource the same call publishes release version 1."""
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

    before = {v["appVersion"] for v in rh.list_app_versions(appArn=app_arn)["appVersions"]}
    assert before == {"draft"}, (
        f"a freshly created app already had versions {sorted(before)}; expected only the draft"
    )

    try:
        published = rh.publish_app_version(appArn=app_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == _ERR_CONFLICT, (
            f"publishing an app with an empty template failed with {code!r}, expected "
            f"{_ERR_CONFLICT!r}. message={exc.response['Error']['Message']!r}"
        )
        message = exc.response["Error"]["Message"]
        expected = "Invalid app template. App template must have at least 1 resource"
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            f"publishing an app whose draft maps no resources succeeded and returned {published!r}; "
            f"real AWS refuses it with {_ERR_CONFLICT}"
        )

    after = {v["appVersion"] for v in rh.list_app_versions(appArn=app_arn)["appVersions"]}
    assert after == {"draft"}, (
        f"the rejected publish left the app with versions {sorted(after)}; a refused publish must "
        "create no release and no numbered version"
    )

    # Positive control: the same call, on the same app, once the draft maps one real resource.
    bucket = ctx.unique_name("sim2real-behav-rh-pub-")
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

    allowed = rh.publish_app_version(appArn=app_arn)
    assert allowed["appVersion"] == "release", (
        f"with one mapped resource the publish returned appVersion {allowed['appVersion']!r}, "
        "expected 'release' -- the rejection above was not about the empty template"
    )
    assert allowed["identifier"] == 1, (
        f"the first successful publish numbered the version {allowed['identifier']!r}, expected 1; "
        "the earlier refused publish must not have consumed a version number"
    )

    final = {
        v["appVersion"]: v["identifier"] for v in rh.list_app_versions(appArn=app_arn)["appVersions"]
    }
    assert set(final) == {"draft", "release"}, (
        f"after the successful publish ListAppVersions returned {sorted(final)}, expected exactly "
        "draft and release"
    )
    assert final["release"] == 1, (
        f"the release alias points at version identifier {final['release']!r}, expected 1 -- the "
        "refused publish must not have consumed a version number"
    )


def _delete_policy_when_released(ctx, policy_arn: str, timeout_s: float = 240.0,
                                interval_s: float = 8.0) -> None:
    """Teardown that waits out the app's reference to its resiliency policy.

    DeleteApp returns before that reference is released, so a policy delete issued straight after it
    is refused with ConflictException for up to a couple of minutes. A policy this check created and
    could not delete is a leaked resource in an account other runs share, so the teardown retries
    rather than giving up on the first conflict. ResourceNotFoundException means the check's own body
    already deleted it.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
