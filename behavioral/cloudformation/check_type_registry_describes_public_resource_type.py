"""type-registry-describes-public-resource-type."""

from __future__ import annotations

import json
import re

from behavioral_harness import tags

CHECK = "type-registry-describes-public-resource-type"
GROUP = "registry"
SERVICES = ["cloudformation"]

# DescribeType's own documented Arn pattern (API_DescribeType): partition and account-id vary
# (account-id is empty for a PUBLIC type), so this is a contract relation, not a pinned value.
_ARN_RE = re.compile(
    r"^arn:aws[A-Za-z0-9-]{0,64}:cloudformation:[A-Za-z0-9-]{1,64}:(\d{12})?:type/resource/.+$"
)


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The extension registry serves AWS's own resource types: DescribeType returns a live
    PUBLIC schema for AWS::SNS::Topic, and ListTypes enumerates public resource types."""
    cfn = ctx.client("cloudformation")
    described = cfn.describe_type(Type="RESOURCE", TypeName="AWS::SNS::Topic")
    assert described["Type"] == "RESOURCE", described["Type"]
    assert described["TypeName"] == "AWS::SNS::Topic", described["TypeName"]
    assert described["Visibility"] == "PUBLIC", described["Visibility"]
    assert described.get("DeprecatedStatus") == "LIVE", described.get(
        "DeprecatedStatus"
    )

    # The registered resource-provider schema is real JSON conforming to the CloudFormation
    # resource-type-schema contract: a "properties" map naming the resource's own fields, not
    # merely a string that happens to contain a matching substring.
    schema = json.loads(described["Schema"])
    assert "properties" in schema, schema.keys()
    assert "TopicName" in schema["properties"], sorted(schema["properties"])

    # The Arn must satisfy DescribeType's own documented pattern for a public resource type in
    # this region (partition/account vary; account-id is absent for PUBLIC), not merely start
    # with a literal prefix.
    assert _ARN_RE.match(described["Arn"]), described["Arn"]
    assert f":cloudformation:{ctx.region}:" in described["Arn"], (
        ctx.region,
        described["Arn"],
    )

    listed = cfn.list_types(Visibility="PUBLIC", Type="RESOURCE", MaxResults=10)
    summaries = listed["TypeSummaries"]
    assert summaries, "expected public resource types in the registry"
    assert all(s["Type"] == "RESOURCE" for s in summaries), summaries


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
