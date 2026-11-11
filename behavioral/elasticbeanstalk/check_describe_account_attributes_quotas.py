"""describe-account-attributes-quotas."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "describe-account-attributes-quotas"
GROUP = 'configuration-metadata'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccountAttributes reports the per-account application/environment quotas."""
    eb = ctx.client("elasticbeanstalk")
    resp = eb.describe_account_attributes()
    quotas = resp["ResourceQuotas"]
    for key in (
        "ApplicationQuota",
        "ApplicationVersionQuota",
        "EnvironmentQuota",
        "ConfigurationTemplateQuota",
        "CustomPlatformQuota",
    ):
        assert key in quotas, f"ResourceQuotas must include {key}"
        maximum = quotas[key]["Maximum"]
        assert isinstance(maximum, int), f"{key}.Maximum must be an int, got {type(maximum).__name__}: {maximum!r}"
        assert maximum > 0, f"{key}.Maximum must be positive, got {maximum!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
