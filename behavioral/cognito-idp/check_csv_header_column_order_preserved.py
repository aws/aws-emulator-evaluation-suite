"""csv-header-column-order-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "csv-header-column-order-preserved"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader returns the same columns on repeated calls, includes every schema attribute, and
    orders them as DescribeUserPool lists the schema."""
    cognito = ctx.client("cognito-idp")

    # Non-alphabetical definition order, so raw input order and a normalized order differ and
    # the comparison against the pool's reported schema is meaningful.
    custom_names = ["zulu", "alpha", "mike"]
    schema = [{"Name": n, "AttributeDataType": "String", "Mutable": True, "Required": False} for n in custom_names]

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-csvpool-"),
        Schema=schema,
        UserPoolTags={"sim2real-check": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    first = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    second = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]

    assert first == second, "GetCSVHeader column order changed between two repeated calls"

    custom_columns = {"custom:" + n for n in custom_names}
    for column in custom_columns:
        assert column in first, f"expected custom attribute column {column!r} missing from CSV header: {first}"

    # DescribeUserPool's schema order is authoritative (Cognito may normalize the request order),
    # so GetCSVHeader is compared against it, not against the creation request.
    pool_schema = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    expected_order = [a["Name"] for a in pool_schema if a["Name"] in custom_columns]

    actual_order = [c for c in first if c in custom_columns]
    assert actual_order == expected_order, (
        f"GetCSVHeader ordered the custom attribute columns as {actual_order}, but the user "
        f"pool's own schema (DescribeUserPool) defines them in order {expected_order}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
