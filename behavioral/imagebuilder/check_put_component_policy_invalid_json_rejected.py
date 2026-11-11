"""put-component-policy-invalid-json-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-component-policy-invalid-json-rejected"
GROUP = "overly-permissive"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutComponentPolicy rejects a malformed (non-JSON) policy document and leaves the component without an attached policy."""
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

    code, message = _error(lambda: ib.put_component_policy(componentArn=arn, policy="{this is not valid json"))
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code!r}"
    expected = "The value supplied for parameter 'policy' is not valid. Policy is malformed and cannot be parsed"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no policy was attached by the rejected call. Image Builder does not raise
    # ResourceNotFoundException for a component with no attached policy — it returns 200 with an
    # empty JSON object as the policy placeholder.
    baseline_policy = ib.get_component_policy(componentArn=arn)["policy"]
    assert baseline_policy == "{}", f"expected empty policy placeholder '{{}}', got {baseline_policy!r}"

    # positive control: a well-formed policy document succeeds and is then reflected verbatim
    principal_arn = f"arn:aws:iam::{account_id}:root"
    valid_policy = json.dumps(
        {
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
    )
    ib.put_component_policy(componentArn=arn, policy=valid_policy)
    got = json.loads(ib.get_component_policy(componentArn=arn)["policy"])
    assert got["Statement"][0]["Action"] == ["imagebuilder:GetComponent"], (
        f"expected reflected policy Action ['imagebuilder:GetComponent'], got {got['Statement'][0]['Action']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected PutComponentPolicy to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
