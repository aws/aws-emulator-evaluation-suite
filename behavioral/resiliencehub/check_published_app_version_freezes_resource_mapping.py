"""published-app-version-freezes-resource-mapping."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "published-app-version-freezes-resource-mapping"
GROUP = 'versioning'
SERVICES = ['resiliencehub']

_STORAGE = 'AWS::ResilienceHub::StorageAppComponent'


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PublishAppVersion snapshots the draft's mapping: deleting a resource from the draft
    afterwards leaves `release` and its template unchanged, and a second publish moves `release` to
    version 2 while version 1 keeps the template it was published with.
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

    app_name = ctx.unique_name("sim2real-behav-rh-app-")
    app_arn = rh.create_app(name=app_name, policyArn=policy_arn)["app"]["appArn"]
    ctx.on_cleanup(lambda: rh.delete_app(appArn=app_arn, forceDelete=True))

    kept_bucket = ctx.unique_name("sim2real-behav-rh-keep-")
    s3.create_bucket(
        Bucket=kept_bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=kept_bucket))

    dropped_bucket = ctx.unique_name("sim2real-behav-rh-drop-")
    s3.create_bucket(
        Bucket=dropped_bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=dropped_bucket))

    component = "sim2real-behav-rh-store"
    rh.create_app_version_app_component(appArn=app_arn, name=component, type=_STORAGE)

    kept_resource = "sim2real-behav-rh-kept"
    dropped_resource = "sim2real-behav-rh-dropped"
    for resource_name, bucket in ((kept_resource, kept_bucket), (dropped_resource, dropped_bucket)):
        rh.create_app_version_resource(
            appArn=app_arn,
            resourceName=resource_name,
            logicalResourceId={"identifier": bucket},
            physicalResourceId=bucket,
            resourceType="AWS::S3::Bucket",
            appComponents=[component],
        )

    published = rh.publish_app_version(appArn=app_arn)
    assert published["appVersion"] == "release", (
        f"first publish returned appVersion {published['appVersion']!r}, expected 'release'"
    )
    assert published["identifier"] == 1, (
        f"first publish numbered the version {published['identifier']!r}, expected 1"
    )

    after_first = {
        v["appVersion"]: v["identifier"] for v in rh.list_app_versions(appArn=app_arn)["appVersions"]
    }
    assert set(after_first) == {"draft", "release"}, (
        f"after one publish ListAppVersions returned {sorted(after_first)}, expected exactly draft "
        "and release -- the newest published version is addressed by the alias, not also listed "
        "under its number"
    )
    assert after_first["release"] == 1, (
        f"the release alias points at version identifier {after_first['release']!r}, expected 1"
    )

    release_at_publish = _resolved_resource_names(ctx, app_arn, "release")
    assert release_at_publish == {kept_resource, dropped_resource}, (
        f"the published release mapped {sorted(release_at_publish)}, expected both resources "
        f"{sorted({kept_resource, dropped_resource})} that the draft held at publish time"
    )
    release_template_at_publish = rh.describe_app_version_template(
        appArn=app_arn, appVersion="release"
    )["appTemplateBody"]

    # Mutate the DRAFT after the publish. This is the only act the two implementations disagree on.
    rh.delete_app_version_resource(appArn=app_arn, resourceName=dropped_resource)

    draft_after_delete = _resolved_resource_names(ctx, app_arn, "draft")
    assert draft_after_delete == {kept_resource}, (
        f"after deleting {dropped_resource!r} the draft still mapped {sorted(draft_after_delete)}, "
        f"expected only {kept_resource!r} -- the delete did not take effect on the draft"
    )

    release_after_delete = _resolved_resource_names(ctx, app_arn, "release")
    assert release_after_delete == {kept_resource, dropped_resource}, (
        f"deleting a resource from the DRAFT changed the release mapping to "
        f"{sorted(release_after_delete)}; a published version must stay frozen at "
        f"{sorted({kept_resource, dropped_resource})}"
    )
    release_template_after_delete = rh.describe_app_version_template(
        appArn=app_arn, appVersion="release"
    )["appTemplateBody"]
    assert release_template_after_delete == release_template_at_publish, (
        "the release app template changed when the draft was edited; expected it byte-identical\n"
        f"at publish:  {release_template_at_publish}\nafter edit: {release_template_after_delete}"
    )

    republished = rh.publish_app_version(appArn=app_arn)
    assert republished["identifier"] == 2, (
        f"the second publish numbered the version {republished['identifier']!r}, expected 2"
    )

    release_after_republish = _resolved_resource_names(ctx, app_arn, "release")
    assert release_after_republish == {kept_resource}, (
        f"after republishing, release mapped {sorted(release_after_republish)}, expected the "
        f"edited draft's {sorted({kept_resource})} -- a publish must move the release pointer"
    )
    version_one_template = rh.describe_app_version_template(appArn=app_arn, appVersion="1")[
        "appTemplateBody"
    ]
    assert version_one_template == release_template_at_publish, (
        "version 1's template changed once version 2 existed; a numbered version is immutable\n"
        f"as published: {release_template_at_publish}\nnow:         {version_one_template}"
    )

    after_second = {
        v["appVersion"]: v["identifier"] for v in rh.list_app_versions(appArn=app_arn)["appVersions"]
    }
    assert set(after_second) == {"draft", "release", "1"}, (
        f"after two publishes ListAppVersions returned {sorted(after_second)}, expected draft, "
        "release and the now-superseded 1 -- republishing must move the alias and leave the old "
        "version addressable by its number"
    )
    assert after_second["release"] == 2, (
        f"the release alias still points at identifier {after_second['release']!r} after the second "
        "publish, expected 2"
    )
    assert after_second["1"] == 1, (
        f"superseded version '1' is listed with identifier {after_second['1']!r}, expected 1"
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


def _resolved_resource_names(
    ctx, app_arn: str, app_version: str, timeout_s: float = 180.0, interval_s: float = 3.0
) -> set:
    """Resolve one app version and return the resource names it maps.

    ListAppVersionResources refuses a version that was never resolved (ResourceResolutionException,
    "Resources were never resolved"), so every read of a mapping has to drive the resolution state
    machine first. Resolution is asynchronous: Pending -> Success in roughly five seconds.
    """
    rh = ctx.client("resiliencehub")
    resolution_id = rh.resolve_app_version_resources(appArn=app_arn, appVersion=app_version)[
        "resolutionId"
    ]
    deadline = time.monotonic() + timeout_s
    status = "Pending"
    while time.monotonic() < deadline:
        status = rh.describe_app_version_resources_resolution_status(
            appArn=app_arn, appVersion=app_version, resolutionId=resolution_id
        )["status"]
        if status != "Pending":
            break
        time.sleep(interval_s)
    assert status == "Success", (
        f"resolving app version {app_version!r} ended in status {status!r}, expected 'Success' "
        f"within {timeout_s:.0f}s (resolutionId {resolution_id})"
    )
    return {
        r["resourceName"]
        for r in rh.list_app_version_resources(appArn=app_arn, appVersion=app_version)[
            "physicalResources"
        ]
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
