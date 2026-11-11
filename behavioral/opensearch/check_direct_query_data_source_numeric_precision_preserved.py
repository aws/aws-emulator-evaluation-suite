"""direct-query-data-source-numeric-precision-preserved."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "direct-query-data-source-numeric-precision-preserved"
GROUP = "data-plane"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A beyond-64-bit integer stored as a digit string in DataSourceAccessPolicy keeps every digit.

    Checked after AddDirectQueryDataSource and UpdateDirectQueryDataSource; the new RoleArn sticks.
    """
    client = ctx.client("opensearch")
    ds_name = _ds_name(ctx)
    role_arn_1 = _dummy_role_arn(ctx, "role-a")
    role_arn_2 = _dummy_role_arn(ctx, "role-b")
    # CloudWatchLog requires OpenSearchArns and rejects domain ARNs ("Opensearch domain not
    # supported yet."); a collection-shaped ARN suffices since only shape and region are validated.
    account = ctx.client("sts").get_caller_identity()["Account"]
    opensearch_arns = [f"arn:aws:aoss:{ctx.region}:{account}:collection/sim2reallprobecollect"]
    resource_arn = f"arn:aws:opensearch:{ctx.region}:{account}:datasource/{ds_name}"

    big_int_1 = 9223372036854775807  # 2**63 - 1
    policy_1 = json.dumps(_policy_with_number(big_int_1, resource_arn))
    client.add_direct_query_data_source(
        DataSourceName=ds_name,
        DataSourceType={"CloudWatchLog": {"RoleArn": role_arn_1}},
        DataSourceAccessPolicy=policy_1,
        OpenSearchArns=opensearch_arns,
        # Tagged at creation so tag-based discovery (Resource Groups Tagging API) can find it.
        TagList=[{"Key": "sim2real", "Value": ds_name}],
    )
    ctx.on_cleanup(lambda: client.delete_direct_query_data_source(DataSourceName=ds_name))

    got1 = client.get_direct_query_data_source(DataSourceName=ds_name)
    # OpenSearch canonicalizes the stored policy (strips whitespace), so compare parsed JSON.
    assert json.loads(got1["DataSourceAccessPolicy"]) == json.loads(policy_1), (
        f"access policy did not round-trip: {got1['DataSourceAccessPolicy']!r}"
    )
    parsed1 = json.loads(got1["DataSourceAccessPolicy"])
    assert _extract_number(parsed1) == big_int_1, (
        f"64-bit-boundary integer did not survive AddDirectQueryDataSource round-trip: "
        f"expected {big_int_1}, got {_extract_number(parsed1)}"
    )

    big_int_2 = 123456789012345678901234567890  # exceeds even 64-bit range
    policy_2 = json.dumps(_policy_with_number(big_int_2, resource_arn))
    client.update_direct_query_data_source(
        DataSourceName=ds_name,
        DataSourceType={"CloudWatchLog": {"RoleArn": role_arn_2}},
        DataSourceAccessPolicy=policy_2,
        OpenSearchArns=opensearch_arns,
    )

    got2 = client.get_direct_query_data_source(DataSourceName=ds_name)
    assert json.loads(got2["DataSourceAccessPolicy"]) == json.loads(policy_2), (
        f"access policy did not round-trip after update: {got2['DataSourceAccessPolicy']!r}"
    )
    parsed2 = json.loads(got2["DataSourceAccessPolicy"])
    assert _extract_number(parsed2) == big_int_2, (
        f"beyond-64-bit integer did not survive UpdateDirectQueryDataSource round-trip: "
        f"expected {big_int_2}, got {_extract_number(parsed2)}"
    )
    assert got2["DataSourceType"]["CloudWatchLog"]["RoleArn"] == role_arn_2, (
        f"UpdateDirectQueryDataSource did not persist the new RoleArn: "
        f"expected {role_arn_2!r}, got {got2['DataSourceType']['CloudWatchLog']['RoleArn']!r}"
    )


def _ds_name(ctx) -> str:
    raw = ctx.unique_name("sim2real_dqds_").lower().replace("-", "_")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "_")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:80]


def _dummy_role_arn(ctx, suffix: str) -> str:
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account}:role/sim2real-nonexistent-{suffix}"


def _policy_with_number(number: int, resource_arn: str) -> dict:
    # The policy is validated as a real IAM resource policy (Principal required, Resource must be
    # a datasource ARN; "*" is rejected as "Incorrect ARN"), so the integer must be a string
    # condition value rather than a raw JSON number.
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realPrecisionProbe",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": [
                    "opensearch:GetDirectQuery",
                    "opensearch:GetDirectQueryResult",
                    "opensearch:CancelDirectQuery",
                    "opensearch:StartDirectQuery",
                ],
                "Resource": resource_arn,

                "Condition": {"StringEquals": {"aws:SourceAccount": str(number)}},
            }
        ],
    }


def _extract_number(policy: dict) -> int:
    return int(policy["Statement"][0]["Condition"]["StringEquals"]["aws:SourceAccount"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
