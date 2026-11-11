"""usage-report-subscription-singleton-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "usage-report-subscription-singleton-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["appstream"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "requires:appstream-service-access")
def run(ctx) -> None:
    """A second CreateUsageReportSubscription while one exists is an idempotent no-op returning
    the existing bucket, so exactly one subscription survives, and re-creating after a delete
    succeeds."""
    appstream = ctx.client("appstream")

    first = _retry_role_propagation(lambda: appstream.create_usage_report_subscription())
    subscription_exists = True
    ctx.on_cleanup(lambda: appstream.delete_usage_report_subscription() if subscription_exists else None)

    subs = appstream.describe_usage_report_subscriptions()["UsageReportSubscriptions"]
    assert len(subs) == 1, f"expected exactly 1 subscription after create, got {len(subs)}"
    original_bucket = subs[0]["S3BucketName"]
    assert original_bucket == first["S3BucketName"], (
        f"describe bucket {original_bucket!r} != create response bucket {first['S3BucketName']!r}"
    )

    # a second call while one already exists must not create a second subscription: real AWS
    # treats it as an idempotent no-op that returns the same bucket
    second = appstream.create_usage_report_subscription()
    assert second["S3BucketName"] == original_bucket, (
        f"idempotent second create returned bucket {second['S3BucketName']!r}, "
        f"expected the original {original_bucket!r}"
    )

    # effect absent: the existing subscription's bucket is unchanged and there is still one
    subs_after = appstream.describe_usage_report_subscriptions()["UsageReportSubscriptions"]
    assert len(subs_after) == 1, f"expected exactly 1 subscription after second create, got {len(subs_after)}"
    assert subs_after[0]["S3BucketName"] == original_bucket, (
        f"subscription bucket changed to {subs_after[0]['S3BucketName']!r} after second create, "
        f"expected unchanged {original_bucket!r}"
    )

    # positive control: delete then re-create succeeds. The independent read between the two
    # proves the delete itself took effect -- without it, a delete that silently no-ops would be
    # masked by create's own idempotent-return-existing-bucket behavior above, and this whole
    # positive control would pass for a target whose delete does nothing.
    appstream.delete_usage_report_subscription()
    subscription_exists = False

    subs_deleted = appstream.describe_usage_report_subscriptions()["UsageReportSubscriptions"]
    assert len(subs_deleted) == 0, f"expected 0 subscriptions after delete, got {len(subs_deleted)}"

    recreated = _retry_role_propagation(lambda: appstream.create_usage_report_subscription())
    subscription_exists = True
    subs_final = appstream.describe_usage_report_subscriptions()["UsageReportSubscriptions"]
    assert len(subs_final) == 1, f"expected exactly 1 subscription after re-create, got {len(subs_final)}"
    assert subs_final[0]["S3BucketName"] == recreated["S3BucketName"], (
        f"describe bucket {subs_final[0]['S3BucketName']!r} != re-create response bucket "
        f"{recreated['S3BucketName']!r}"
    )


def _retry_role_propagation(fn, timeout_s: float = 90.0):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
