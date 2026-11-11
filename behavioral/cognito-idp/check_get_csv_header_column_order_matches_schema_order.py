"""get-csv-header-column-order-matches-schema-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-csv-header-column-order-matches-schema-order"
GROUP = "ordering"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader lists every custom attribute in the relative order DescribeUserPool's schema
    reports, and returns the same header on repeated calls."""
    idp = ctx.client("cognito-idp")

    # Deliberately non-alphabetical so a target whose GetCSVHeader independently
    # alphabetizes (rather than following the schema's own order) cannot coincide
    # with the expected order by accident.
    custom_names = ["zzzfirst", "mmmsecond", "aaathird"]
    schema = [
        {"Name": n, "AttributeDataType": "String", "Mutable": True, "Required": False}
        for n in custom_names
    ]
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        Schema=schema,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    # Authoritative order: read the pool's own schema back rather than assuming
    # the create-time request order was preserved verbatim. AWS prefixes custom
    # attribute names with "custom:" in the DescribeUserPool response even though
    # the CreateUserPool request supplied bare names.
    described_schema = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    described_custom_names = [
        attr["Name"][len("custom:"):]
        for attr in described_schema
        if attr["Name"].startswith("custom:") and attr["Name"][len("custom:"):] in custom_names
    ]
    expected_columns = [f"custom:{n}" for n in described_custom_names]
    assert sorted(described_custom_names) == sorted(custom_names), (
        f"not all custom attributes present in DescribeUserPool schema: {described_schema}"
    )

    header_1 = idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    header_2 = idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"]

    # Stability: repeated calls return the identical column order.
    assert header_1 == header_2, (
        f"GetCSVHeader is not deterministic across repeated calls: {header_1} != {header_2}"
    )

    indices = []
    for col in expected_columns:
        assert col in header_1, f"{col} missing from CSVHeader: {header_1}"
        indices.append(header_1.index(col))

    assert indices == sorted(indices), (
        f"CSVHeader custom columns {[' '.join(expected_columns)]} are not in the pool's own "
        f"schema order {expected_columns}: full header={header_1}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
