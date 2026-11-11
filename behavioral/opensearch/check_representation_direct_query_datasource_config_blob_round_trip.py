"""representation-direct-query-datasource-config-blob-round-trip."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "representation-direct-query-datasource-config-blob-round-trip"
GROUP = "representation"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDirectQueryDataSource returns the access policy minified, keys, values and order intact;
    an update whose policy embeds a newline raises ValidationException and changes nothing.
    """
    opensearch = ctx.client("opensearch")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_name = f"sim2real-behav-dq-{uuid.uuid4().hex[:10]}"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "opensearchservice.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    ds_name = f"sim2real_dq_{uuid.uuid4().hex[:10]}"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [
                    "opensearch:StartDirectQuery",
                    "opensearch:GetDirectQuery",
                    "opensearch:CancelDirectQuery",
                    "opensearch:GetDirectQueryResult",
                ],
                "Resource": f"arn:aws:opensearch:{ctx.region}:{account_id}:datasource/{ds_name}",
            }
        ],
    }
    # Deliberately NOT the compact form (default separators put a space after every ":" and
    # ","), so storing the blob verbatim and re-serializing it are distinguishable.
    access_policy = json.dumps(policy_doc)
    minified_policy = json.dumps(policy_doc, separators=(",", ":"))
    assert access_policy != minified_policy, "sent policy was already in compact form -- test is vacuous"

    data_source_type = {"CloudWatchLog": {"RoleArn": role_arn}}
    opensearch_arns = [f"arn:aws:aoss:{ctx.region}:{account_id}:collection/0123456789abcdef01"]
    opensearch.add_direct_query_data_source(
        DataSourceName=ds_name,
        DataSourceType=data_source_type,
        Description="sim2real behavioral fidelity check direct query data source",
        DataSourceAccessPolicy=access_policy,
        OpenSearchArns=opensearch_arns,
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: opensearch.delete_direct_query_data_source(DataSourceName=ds_name))

    fetched = opensearch.get_direct_query_data_source(DataSourceName=ds_name)
    assert fetched["DataSourceName"] == ds_name
    assert fetched["DataSourceType"]["CloudWatchLog"]["RoleArn"] == role_arn
    got_policy = fetched["DataSourceAccessPolicy"]
    if got_policy != minified_policy:
        i = next(
            (i for i, (a, b) in enumerate(zip(got_policy, minified_policy)) if a != b),
            min(len(got_policy), len(minified_policy)),
        )
        raise AssertionError(
            f"diff@{i} got={got_policy[max(0,i-5):i+20]!r} "
            f"expected(minified)={minified_policy[max(0,i-5):i+20]!r} "
            f"lens got={len(got_policy)} expected={len(minified_policy)}"
        )
    # Content and array order survive the server-side re-serialization untouched.
    assert json.loads(got_policy)["Statement"][0]["Action"] == [
        "opensearch:StartDirectQuery",
        "opensearch:GetDirectQuery",
        "opensearch:CancelDirectQuery",
        "opensearch:GetDirectQueryResult",
    ]

    # The dataSourceAccessPolicy constraint is the pattern `.*`, which does not match across a
    # newline, so this is rejected rather than reformatted like the whitespace above.
    policy_with_newline = json.dumps(policy_doc, indent=2)
    try:
        opensearch.update_direct_query_data_source(
            DataSourceName=ds_name,
            DataSourceType=data_source_type,
            OpenSearchArns=opensearch_arns,
            DataSourceAccessPolicy=policy_with_newline,
        )
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code")
        message = err.response.get("Error", {}).get("Message")
        assert code == "ValidationException", f"expected ValidationException, got {code!r}"
        expected = (
            f"1 validation error detected: Value '{policy_with_newline}' at 'dataSourceAccessPolicy' "
            "failed to satisfy constraint: Member must satisfy regular expression pattern: .*"
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError("update with a newline-embedded access policy was accepted")

    # Effect-absent: the rejected update must not have touched the stored policy.
    unchanged = opensearch.get_direct_query_data_source(DataSourceName=ds_name)
    assert unchanged["DataSourceAccessPolicy"] == minified_policy, (
        "rejected update mutated the stored access policy"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
