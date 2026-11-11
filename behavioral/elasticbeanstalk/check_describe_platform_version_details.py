"""describe-platform-version-details."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "describe-platform-version-details"
GROUP = 'platform-versions'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePlatformVersion returns a full description matching a summary from the list."""
    eb = ctx.client("elasticbeanstalk")
    listed = eb.list_platform_versions(MaxRecords=1)
    platforms = listed["PlatformSummaryList"]
    if not platforms:
        raise AssertionError("no platform versions available to describe")
    summary = platforms[0]
    arn = summary["PlatformArn"]

    described = eb.describe_platform_version(PlatformArn=arn)
    desc = described["PlatformDescription"]
    assert desc["PlatformArn"] == arn, (
        f"DescribePlatformVersion PlatformArn mismatch: expected {arn!r}, got {desc['PlatformArn']!r}"
    )
    assert desc["PlatformStatus"] == summary["PlatformStatus"], (
        "DescribePlatformVersion PlatformStatus must match the ListPlatformVersions summary for "
        f"the same ARN: expected {summary['PlatformStatus']!r}, got {desc['PlatformStatus']!r}"
    )
    assert desc["PlatformOwner"] == summary["PlatformOwner"], (
        "DescribePlatformVersion PlatformOwner must match the ListPlatformVersions summary for "
        f"the same ARN: expected {summary['PlatformOwner']!r}, got {desc['PlatformOwner']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
