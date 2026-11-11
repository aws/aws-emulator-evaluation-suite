"""create-distribution-configuration-get-roundtrip."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-distribution-configuration-get-roundtrip"
GROUP = "crud-roundtrip"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDistributionConfiguration persists the per-region distribution list, visible via Get;
    once deleted, the arn is dead for both an independent read and a mutation."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-dist-")
    ami_name = ctx.unique_name("sim2real-ib-ami-") + "-{{ imagebuilder:buildDate }}"
    resp = ib.create_distribution_configuration(
        name=name,
        distributions=[
            {
                "region": ctx.region,
                "amiDistributionConfiguration": {"name": ami_name},
            }
        ],
        tags={"sim2real-check": CHECK},
        clientToken=str(uuid.uuid4()),
    )
    arn = resp["distributionConfigurationArn"]
    ctx.on_cleanup(_ignore_not_found(lambda: ib.delete_distribution_configuration(distributionConfigurationArn=arn)))

    got = ib.get_distribution_configuration(distributionConfigurationArn=arn)["distributionConfiguration"]
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["arn"] == arn, f"expected arn {arn!r}, got {got['arn']!r}"
    assert len(got["distributions"]) == 1, f"expected exactly 1 distribution, got {len(got['distributions'])}"
    assert got["distributions"][0]["region"] == ctx.region, (
        f"expected region {ctx.region!r}, got {got['distributions'][0]['region']!r}"
    )
    assert got["distributions"][0]["amiDistributionConfiguration"]["name"] == ami_name, (
        f"expected ami name {ami_name!r}, got {got['distributions'][0]['amiDistributionConfiguration']['name']!r}"
    )

    ib.delete_distribution_configuration(distributionConfigurationArn=arn)
    expected = f"The following required resource 'DistributionConfiguration' cannot be found: '{arn}'."
    try:
        ib.get_distribution_configuration(distributionConfigurationArn=arn)
    except ClientError as e:
        code, msg = e.response["Error"]["Code"], e.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
        assert msg == expected, f"expected message {expected!r}, got {msg!r}"
    else:
        raise AssertionError("expected get_distribution_configuration to fail after delete, but it succeeded")

    try:
        ib.update_distribution_configuration(
            distributionConfigurationArn=arn,
            distributions=[{"region": ctx.region, "amiDistributionConfiguration": {"name": ami_name}}],
            clientToken=str(uuid.uuid4()),
        )
    except ClientError as e:
        code, msg = e.response["Error"]["Code"], e.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", (
            f"expected a mutation on the deleted arn to fail with ResourceNotFoundException, got {code!r}"
        )
        assert msg == expected, f"expected message {expected!r}, got {msg!r}"
    else:
        raise AssertionError("expected update_distribution_configuration on a deleted arn to fail, but it succeeded")


def _ignore_not_found(fn):
    """Teardown wrapper: a resource the check already deleted reads as not-found; anything else raises."""
    def go():
        try:
            fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    return go


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
