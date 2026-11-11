"""get-csv-header-empty-custom-schema-returns-empty-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-csv-header-empty-custom-schema-returns-empty-list"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader on a pool with no custom attributes returns the pool id and a non-empty CSVHeader
    list with no custom: columns, and on a pool id never created fails with
    ResourceNotFoundException and its exact message."""
    from botocore.exceptions import ClientError

    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-csvhdr-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-csvhdr"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    resp = cognito.get_csv_header(UserPoolId=pool_id)
    assert "CSVHeader" in resp, f"expected CSVHeader in response, got keys {sorted(resp)}"
    header = resp["CSVHeader"]
    assert isinstance(header, list), f"expected CSVHeader to be a list, got {type(header).__name__}"
    assert len(header) > 0, "expected a non-empty CSVHeader (standard attributes) even with no custom schema"

    custom_segment = [name for name in header if name.startswith("custom:") or name.startswith("dev:custom:")]
    assert custom_segment == [], f"expected no custom: columns for a pool with no custom attributes, got {custom_segment}"
    assert resp["UserPoolId"] == pool_id, f"expected UserPoolId {pool_id!r}, got {resp['UserPoolId']!r}"

    region = cognito.meta.region_name
    bogus_pool_id = f"{region}_sim2realNoSuchPool000"
    try:
        cognito.get_csv_header(UserPoolId=bogus_pool_id)
    except ClientError as exc:
        error = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError("expected ResourceNotFoundException for a nonexistent UserPoolId")
    assert error == ("ResourceNotFoundException", f"User pool {bogus_pool_id} does not exist."), (
        f"expected ResourceNotFoundException, got {error!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
