"""csv-header-schema-matches-pool-custom-attributes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "csv-header-schema-matches-pool-custom-attributes"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader's column names exactly match the pool's configured custom attribute
    schema, including case and the custom: prefix."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-csvpool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-csvpool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    attr_name = "MyOddlyCasedFieldXyz"
    idp.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[{"Name": attr_name, "AttributeDataType": "String", "Mutable": True}],
    )

    header = idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    expected_column = f"custom:{attr_name}"
    assert expected_column in header, f"expected column {expected_column!r} in CSV header {header!r}"
    # Case must match exactly: a case-folded variant of our mixed-case attribute name must
    # not appear instead of (or in addition to) the exact-case column.
    lowered = expected_column.lower()
    assert lowered != expected_column
    assert lowered not in header


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
