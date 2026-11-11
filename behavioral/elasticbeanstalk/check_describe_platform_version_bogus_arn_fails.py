"""describe-platform-version-bogus-arn-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-platform-version-bogus-arn-fails"
GROUP = 'platform-versions'
SERVICES = ['elasticbeanstalk']

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting an ARN real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this ARN, but the call SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribePlatformVersion with a well-formed but nonexistent platform ARN fails with InvalidParameterValue and
    the exact message, while a real platform ARN describes normally."""
    eb = ctx.client("elasticbeanstalk")

    listed = eb.list_platform_versions(MaxRecords=1)["PlatformSummaryList"]
    if not listed:
        raise AssertionError("no platform versions available for the positive control")
    real_arn = listed[0]["PlatformArn"]
    control = eb.describe_platform_version(PlatformArn=real_arn)["PlatformDescription"]
    assert control["PlatformArn"] == real_arn, (
        f"positive control: DescribePlatformVersion for a real platform must return that "
        f"platform, got {control.get('PlatformArn')!r}"
    )

    bogus = (
        f"arn:aws:elasticbeanstalk:{ctx.region}::platform/"
        f"{ctx.unique_name('sim2real-behav-NoSuchPlatform-')}/1.0.0"
    )
    error = _client_error(lambda: eb.describe_platform_version(PlatformArn=bogus))
    assert error.get("Code") == "InvalidParameterValue", (
        f"DescribePlatformVersion for a nonexistent platform must fail with "
        f"InvalidParameterValue, got {error.get('Code')!r}"
    )
    expected = f"Platform '{bogus}' does not exist."
    assert error.get("Message") == expected, (
        f"DescribePlatformVersion for a nonexistent platform must say {expected!r}, "
        f"got {error.get('Message')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
