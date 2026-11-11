"""get-csv-header-deterministic-across-repeated-calls."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-csv-header-deterministic-across-repeated-calls"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated GetCSVHeader calls against an unchanged pool schema return the exact
    same, server-generated header row every time -- deterministic column set and column
    order, with no caller-supplied variance between identical requests."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-csvheader-pool-"),
        Schema=[
            {"Name": "loyaltytier", "AttributeDataType": "String", "Mutable": True},
            {"Name": "signupscore", "AttributeDataType": "Number", "Mutable": True},
        ],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-csvheader"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    headers = [idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"] for _ in range(5)]

    first = headers[0]
    assert first, "GetCSVHeader returned an empty header"
    assert "custom:loyaltytier" in first, f"expected custom:loyaltytier in CSV header, got {first}"
    assert "custom:signupscore" in first, f"expected custom:signupscore in CSV header, got {first}"
    for other in headers[1:]:
        assert other == first, f"GetCSVHeader varied between repeated calls: {other} != {first}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
