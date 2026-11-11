"""validate-template-returns-parameters."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "validate-template-returns-parameters"
GROUP = 'template_validation'
SERVICES = ['cloudformation']


def _parameters_template(*, default=None, allowed_values=None, no_echo=False):
    param = {"Type": "String", "Description": "Queue suffix"}
    if default is not None:
        param["Default"] = default
    if allowed_values:
        param["AllowedValues"] = allowed_values
    if no_echo:
        param["NoEcho"] = True
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Suffix": param},
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {"ParamValue": {"Value": {"Ref": "Suffix"}}},
    })


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidateTemplate returns declared parameters, including default value,
    description and NoEcho."""
    cf = ctx.client("cloudformation")
    resp = cf.validate_template(
        TemplateBody=_parameters_template(default="x", allowed_values=["x", "y"], no_echo=True)
    )
    params = resp.get("Parameters", [])
    assert len(params) == 1, f"expected 1 declared parameter, got {params}"
    param = params[0]
    assert param["ParameterKey"] == "Suffix", f"expected ParameterKey 'Suffix', got {param}"
    assert param.get("DefaultValue") == "x", (
        f"expected DefaultValue 'x', got {param.get('DefaultValue')!r}"
    )
    assert param.get("Description") == "Queue suffix", (
        f"expected Description 'Queue suffix', got {param.get('Description')!r}"
    )
    assert param.get("NoEcho") is True, f"expected NoEcho True, got {param.get('NoEcho')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
