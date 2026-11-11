"""get-csv-header-matches-custom-schema-attribute-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-csv-header-matches-custom-schema-attribute-order"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After adding custom attributes to a pool, GetCSVHeader returns a header row
    whose custom-attribute columns are present and appear in the exact order the
    attributes were added -- not re-sorted alphabetically or by any other order."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    # Deliberately non-alphabetical insertion order to prove the header preserves
    # insertion order rather than sorting the columns.
    ordered_names = ["zzzattr", "aaaattr", "mmmattr"]
    idp.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {"Name": name, "AttributeDataType": "String", "Mutable": True} for name in ordered_names
        ],
    )

    header = idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    expected_columns = [f"custom:{name}" for name in ordered_names]
    for col in expected_columns:
        assert col in header, f"{col} missing from CSVHeader: {header}"

    indices = [header.index(col) for col in expected_columns]
    assert indices == sorted(indices), f"custom attribute columns are not in insertion order: {header}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
