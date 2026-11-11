"""validate-template-capabilities."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "validate-template-capabilities"
GROUP = 'validate'
SERVICES = ['cloudformation']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidateTemplate reports CAPABILITY_NAMED_IAM for a template that names its IAM
    role explicitly, and only the weaker CAPABILITY_IAM for the same role left unnamed —
    the contrast a stub that always claims CAPABILITY_NAMED_IAM would not survive."""
    cfn = ctx.client("cloudformation")
    role_name = ctx.unique_name("sim2real-behav-cfn-validate-role-")

    named = cfn.validate_template(TemplateBody=_iam_role_template(role_name))
    assert "CAPABILITY_NAMED_IAM" in named.get("Capabilities", []), named.get("Capabilities")
    assert "AWS::IAM::Role" in named.get("CapabilitiesReason", ""), named.get("CapabilitiesReason")

    unnamed = cfn.validate_template(TemplateBody=_iam_role_template(None))
    assert "CAPABILITY_NAMED_IAM" not in unnamed.get("Capabilities", []), unnamed.get("Capabilities")
    assert "CAPABILITY_IAM" in unnamed.get("Capabilities", []), unnamed.get("Capabilities")


def _iam_role_template(role_name) -> str:
    """A single IAM role; naming it forces CAPABILITY_NAMED_IAM instead of CAPABILITY_IAM."""
    properties = {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    }
    if role_name:
        properties["RoleName"] = role_name
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"MyRole": {"Type": "AWS::IAM::Role", "Properties": properties}},
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
