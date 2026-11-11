"""list-platform-versions-smoke."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "list-platform-versions-smoke"
GROUP = 'platform-versions'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPlatformVersions returns at least the built-in AWS-managed platforms."""
    eb = ctx.client("elasticbeanstalk")
    resp = eb.list_platform_versions()
    platforms = resp["PlatformSummaryList"]
    assert len(platforms) > 0, "expected a non-empty platform version catalog"
    for p in platforms:
        arn = p["PlatformArn"]
        assert arn.startswith("arn:aws:elasticbeanstalk:"), f"malformed PlatformArn: {arn!r}"
        assert ":platform/" in arn, f"PlatformArn missing platform resource segment: {arn!r}"
    owners = {p.get("PlatformOwner") for p in platforms}
    assert "AWSElasticBeanstalk" in owners, (
        f"expected the AWS-managed catalog owner 'AWSElasticBeanstalk' among PlatformOwner "
        f"values, got owners={owners!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
