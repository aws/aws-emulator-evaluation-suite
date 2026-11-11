"""application-lifecycle-activates-on-component-monitoring."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-lifecycle-activates-on-component-monitoring"
GROUP = "application-lifecycle"
SERVICES = ["application-insights"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An application stays NOT_CONFIGURED until a discovered component is monitored, then
    its LifeCycle transitions to ACTIVE without any further call.

    Reference: https://docs.aws.amazon.com/application-insights/latest/APIReference/API_DescribeApplication.html
    """
    s3 = ctx.client("s3")
    rg = ctx.client("resource-groups")
    ai = ctx.client("application-insights")

    tag_key = ctx.unique_name("sim2real-behav-ai-tag-")
    bucket = ctx.unique_name("sim2real-behav-ai-bkt-")

    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": tag_key, "Value": "1"}]})
    bucket_arn = f"arn:aws:s3:::{bucket}"

    group_name = ctx.unique_name("sim2real-behav-ai-group-")
    rg.create_group(
        Name=group_name,
        ResourceQuery={
            "Type": "TAG_FILTERS_1_0",
            "Query": json.dumps(
                {
                    "ResourceTypeFilters": ["AWS::AllSupported"],
                    "TagFilters": [{"Key": tag_key, "Values": ["1"]}],
                }
            ),
        },
    )
    ctx.on_cleanup(_teardown(lambda: rg.delete_group(GroupName=group_name), "NotFoundException"))

    ai.create_application(ResourceGroupName=group_name, AutoConfigEnabled=False)
    ctx.on_cleanup(
        _teardown(
            lambda: ai.delete_application(ResourceGroupName=group_name), "ResourceNotFoundException"
        )
    )

    lifecycle_before = ai.describe_application(ResourceGroupName=group_name)["ApplicationInfo"][
        "LifeCycle"
    ]
    assert lifecycle_before in {"CREATING", "NOT_CONFIGURED"}, (
        f"a freshly created, unmonitored application reported LifeCycle {lifecycle_before!r}"
    )

    components = _poll_until(
        lambda: ai.list_components(ResourceGroupName=group_name)["ApplicationComponentList"],
        lambda cs: any(c["ComponentName"] == bucket_arn for c in cs),
        timeout_s=240,
        interval_s=10,
        description="the bucket to be auto-discovered as a default component",
    )
    discovered = next(c for c in components if c["ComponentName"] == bucket_arn)
    assert discovered["Monitor"] is False, (
        f"a freshly discovered component must start unmonitored: {discovered!r}"
    )

    lifecycle_still_unconfigured = _poll_until(
        lambda: ai.describe_application(ResourceGroupName=group_name)["ApplicationInfo"][
            "LifeCycle"
        ],
        lambda lc: lc != "CREATING",
        timeout_s=240,
        interval_s=10,
        description="the application to leave the transient CREATING state",
    )
    assert lifecycle_still_unconfigured == "NOT_CONFIGURED", (
        f"with every discovered component unmonitored, LifeCycle should settle on NOT_CONFIGURED, "
        f"got {lifecycle_still_unconfigured!r}"
    )

    ai.update_component_configuration(
        ResourceGroupName=group_name,
        ComponentName=bucket_arn,
        Monitor=True,
        Tier="DEFAULT",
        ComponentConfiguration=json.dumps({"subComponents": []}),
    )

    described = ai.describe_component_configuration(
        ResourceGroupName=group_name, ComponentName=bucket_arn
    )
    assert described["Monitor"] is True, (
        f"UpdateComponentConfiguration did not take effect: {described!r}"
    )

    lifecycle_active = _poll_until(
        lambda: ai.describe_application(ResourceGroupName=group_name)["ApplicationInfo"][
            "LifeCycle"
        ],
        lambda lc: lc == "ACTIVE",
        timeout_s=240,
        interval_s=10,
        description="the application to become ACTIVE once a component is monitored",
    )
    assert lifecycle_active == "ACTIVE", lifecycle_active

    components_after = ai.list_components(ResourceGroupName=group_name)["ApplicationComponentList"]
    monitored = next(c for c in components_after if c["ComponentName"] == bucket_arn)
    assert monitored["Monitor"] is True, (
        f"ListComponents must reflect the monitoring flag set via UpdateComponentConfiguration: {monitored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
