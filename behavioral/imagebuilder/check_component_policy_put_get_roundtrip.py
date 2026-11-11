"""component-policy-put-get-roundtrip."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "component-policy-put-get-roundtrip"
GROUP = "resource-policy"
SERVICES = ["imagebuilder"]

_COMPONENT_DATA = """
name: sim2real-test-component
description: minimal test component
schemaVersion: 1.0

phases:
  - name: build
    steps:
      - name: HelloWorldStep
        action: ExecuteBash
        inputs:
          commands:
            - echo "hello world"
""".strip()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutComponentPolicy attaches a resource policy that GetComponentPolicy then returns verbatim."""
    ib = ctx.client("imagebuilder")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-component-")
    arn = ib.create_component(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=_COMPONENT_DATA,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))

    principal_arn = f"arn:aws:iam::{account_id}:root"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": [principal_arn]},
                "Action": ["imagebuilder:GetComponent"],
                "Resource": [arn],
            }
        ],
    }
    ib.put_component_policy(componentArn=arn, policy=json.dumps(policy_doc))

    got = json.loads(ib.get_component_policy(componentArn=arn)["policy"])
    assert got["Statement"][0]["Action"] == ["imagebuilder:GetComponent"]
    assert got["Statement"][0]["Principal"]["AWS"] == principal_arn, f"expected {principal_arn!r}, got {got['Statement'][0]['Principal']['AWS']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
