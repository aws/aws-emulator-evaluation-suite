"""update-distribution-configuration-persists-new-region."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-distribution-configuration-persists-new-region"
GROUP = "deploy"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDistributionConfiguration replaces the distributions list; GetDistributionConfiguration reflects it."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-dist-")
    ami_name = "sim2real-{{ imagebuilder:buildDate }}"
    resp = ib.create_distribution_configuration(
        name=name,
        distributions=[{"region": ctx.region, "amiDistributionConfiguration": {"name": ami_name}}],
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )
    arn = resp["distributionConfigurationArn"]

    def _cleanup():
        try:
            ib.delete_distribution_configuration(distributionConfigurationArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = ib.get_distribution_configuration(distributionConfigurationArn=arn)["distributionConfiguration"]
    regions_before = [d["region"] for d in got["distributions"]]
    assert regions_before == [ctx.region], f"expected [{ctx.region!r}] right after create, got {regions_before!r}"

    # other_region only needs to be *some* AWS region distinct from ctx.region: the
    # subject under test is the region list changing, not this specific region's identity.
    other_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    ib.update_distribution_configuration(
        distributionConfigurationArn=arn,
        distributions=[
            {"region": ctx.region, "amiDistributionConfiguration": {"name": ami_name}},
            {"region": other_region, "amiDistributionConfiguration": {"name": ami_name}},
        ],
        clientToken=str(uuid.uuid4()),
    )

    got_after = ib.get_distribution_configuration(distributionConfigurationArn=arn)["distributionConfiguration"]
    regions_after = sorted(d["region"] for d in got_after["distributions"])
    expected_regions = sorted([ctx.region, other_region])
    assert regions_after == expected_regions, (
        f"expected distributions regions {expected_regions!r} after update, got {regions_after!r}"
    )

    ib.delete_distribution_configuration(distributionConfigurationArn=arn)
    code, message = _error_code(lambda: ib.get_distribution_configuration(distributionConfigurationArn=arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted distribution configuration, got {code!r}"
    )
    assert message == f"The following required resource 'DistributionConfiguration' cannot be found: '{resp['distributionConfigurationArn']}'.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message!r}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the call to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
