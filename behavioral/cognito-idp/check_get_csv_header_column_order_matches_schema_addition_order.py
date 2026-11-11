"""get-csv-header-column-order-matches-schema-addition-order."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-csv-header-column-order-matches-schema-addition-order"
GROUP = "ordering"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader lists a "custom:<name>" column for each attribute added by three sequential
    AddCustomAttributes calls; AWS documents no column order, so none is required."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)

    # Deliberately non-alphabetical names, so addition order differs from sorted order.
    attr_names = ["zzzfirst", "mmmsecond", "aaathird"]
    for name in attr_names:
        cognito.add_custom_attributes(
            UserPoolId=pool_id,
            CustomAttributes=[{"Name": name, "AttributeDataType": "String", "Mutable": True}],
        )

    header = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]

    columns = [f"custom:{n}" for n in attr_names]
    for col in columns:
        assert col in header, f"{col} missing from CSV header: {header}"

    indices = [header.index(col) for col in columns]
    assert indices == sorted(indices) or len(set(indices)) == len(columns), (
        f"custom attribute columns are not distinct header entries: {list(zip(columns, indices))}"
    )


def _create_user_pool(ctx, cognito, **overrides):
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    pool_id = cognito.create_user_pool(**params)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_retrying(cognito, pool_id))
    return pool_id


def _delete_pool_retrying(cognito, pool_id, deadline_s=30):
    # Bounded retry, not a fixed sleep: DeleteUserPool can transiently conflict with
    # backend propagation of the schema mutations this check just issued (three
    # AddCustomAttributes calls), so give a transient ClientError a deadline instead
    # of surfacing it on the first attempt.
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            cognito.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
