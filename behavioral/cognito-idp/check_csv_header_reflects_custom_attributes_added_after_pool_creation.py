"""csv-header-reflects-custom-attributes-added-after-pool-creation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "csv-header-reflects-custom-attributes-added-after-pool-creation"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom attribute added via AddCustomAttributes after pool creation
    appears in a subsequent GetCSVHeader call, proving the header is computed
    live from current schema rather than cached at creation time."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    baseline = idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    assert "custom:extraattr" not in baseline, (
        f"custom:extraattr already present before AddCustomAttributes: {baseline!r}"
    )

    idp.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {"Name": "extraattr", "AttributeDataType": "String", "Mutable": True, "Required": False}
        ],
    )

    updated = idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    assert "custom:extraattr" in updated, f"expected custom:extraattr in {updated!r}"
    # len+1 and an exact set difference pin the whole delta, not just the new column,
    # so a target that also dropped or renamed an existing column cannot pass.
    assert len(updated) == len(baseline) + 1, (
        f"expected exactly one new column: baseline={baseline!r} updated={updated!r}"
    )
    assert set(updated) - set(baseline) == {"custom:extraattr"}, (
        f"unexpected column delta: baseline={baseline!r} updated={updated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
