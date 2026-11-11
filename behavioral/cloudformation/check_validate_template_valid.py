"""validate-template-valid."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "validate-template-valid"
GROUP = 'template_validation'
SERVICES = ['cloudformation']


def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidateTemplate on a valid template with no Parameters section and no IAM
    resources reports zero declared parameters and zero required capabilities."""
    cf = ctx.client("cloudformation")
    resp = cf.validate_template(TemplateBody=_handle_template())
    assert resp.get("Parameters") == [], (
        f"expected no declared parameters for a template with no Parameters section, "
        f"got {resp.get('Parameters')!r}"
    )
    assert resp.get("Capabilities", []) == [], (
        f"expected no required capabilities for a template with no IAM resources, "
        f"got {resp.get('Capabilities')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
