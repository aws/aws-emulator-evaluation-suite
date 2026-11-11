"""csv-header-reflects-schema-lifecycle-after-attribute-addition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "csv-header-reflects-schema-lifecycle-after-attribute-addition"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader output changes state after AddCustomAttributes is
    called, reflecting the new schema without requiring pool recreation."""
    cognito = ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-csv-pool-")
    pool_id = cognito.create_user_pool(
        PoolName=pool_name, UserPoolTags={"sim2real-check": CHECK}
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    attribute_name = "loyaltytier"
    custom_header = f"custom:{attribute_name}"

    before = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    assert custom_header not in before, f"{custom_header} unexpectedly present before AddCustomAttributes: {before}"

    cognito.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {"Name": attribute_name, "AttributeDataType": "String", "Mutable": True}
        ],
    )

    after = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    assert custom_header in after, f"expected {custom_header} in CSV header after AddCustomAttributes, got {after}"
    assert len(after) == len(before) + 1, (
        f"expected header to grow by exactly 1 column, before={before} after={after}"
    )
    assert set(after) - set(before) == {custom_header}, (
        f"expected the only new column to be {custom_header}, before={before} after={after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
