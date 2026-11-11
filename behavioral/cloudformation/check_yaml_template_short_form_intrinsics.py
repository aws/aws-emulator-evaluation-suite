"""yaml-template-short-form-intrinsics."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "yaml-template-short-form-intrinsics"
GROUP = 'template_validation'
SERVICES = ['cloudformation']

# ===== helpers =====
_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it no longer exists."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError:
        return None


def _wait_terminal(cf, name, *, timeout_s=600, interval_s=5):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


# ===== end helpers =====

_DESCRIPTION = "sim2real yaml short-form intrinsic probe"

# Deliberately exercises: a folded block scalar, a flow sequence, both the
# single-line (!Ref X) and nested (!Select [1, !Split [...]]) short forms, a
# short-form Condition (!Equals), a block-sequence !Join, and !GetAtt with the
# dotted attribute form.
_YAML = """AWSTemplateFormatVersion: '2010-09-09'
Description: >-
  sim2real yaml
  short-form intrinsic probe
Parameters:
  Env:
    Type: String
    Default: dev
    AllowedValues: [dev, prod]
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Param:
    Type: AWS::SSM::Parameter
    Properties:
      Name: __PARAM_NAME__
      Type: String
      Value: !Join
        - '-'
        - - !Ref Env
          - !Select [1, !Split ['|', 'alpha|beta|gamma']]
          - !If [IsProd, gold, bronze]
Outputs:
  Combined:
    Value: !Sub '${Param}::${AWS::Region}'
  ViaGetAtt:
    Value: !GetAtt Param.Value
  TierFlag:
    Value: !If [IsProd, 'yes', 'no']
"""

_JSON_TWIN = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": _DESCRIPTION,
    "Parameters": {"Env": {"Type": "String", "Default": "dev",
                           "AllowedValues": ["dev", "prod"]}},
    "Conditions": {"IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}},
    "Resources": {
        "Param": {
            "Type": "AWS::SSM::Parameter",
            "Properties": {
                "Name": "__PARAM_NAME__",
                "Type": "String",
                "Value": {"Fn::Join": ["-", [
                    {"Ref": "Env"},
                    {"Fn::Select": ["1", {"Fn::Split": ["|", "alpha|beta|gamma"]}]},
                    {"Fn::If": ["IsProd", "gold", "bronze"]},
                ]]},
            },
        },
    },
    "Outputs": {
        "Combined": {"Value": {"Fn::Sub": "${Param}::${AWS::Region}"}},
        "ViaGetAtt": {"Value": {"Fn::GetAtt": ["Param", "Value"]}},
        "TierFlag": {"Value": {"Fn::If": ["IsProd", "yes", "no"]}},
    },
}


def _yaml_body(param_name):
    return _YAML.replace("__PARAM_NAME__", param_name)


def _json_body(param_name):
    return json.dumps(_JSON_TWIN).replace("__PARAM_NAME__", param_name)


def _deploy(ctx, cf, body, param_name, env):
    stack = ctx.unique_name("sim2real-behav-yaml-")
    cf.create_stack(
        StackName=stack, TemplateBody=body,
        Parameters=[{"ParameterKey": "Env", "ParameterValue": env}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    stack_obj = _wait_terminal(cf, stack)
    assert stack_obj["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack} must reach CREATE_COMPLETE, got {stack_obj['StackStatus']!r}: "
        f"{stack_obj.get('StackStatusReason')!r}"
    )
    return stack, stack_obj


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A YAML template with short-form intrinsic tags, a folded block scalar and flow sequences is
    evaluated identically to its long-form JSON twin: same resolved property, Outputs and
    GetTemplateSummary projection.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    yaml_param = "/" + ctx.unique_name("sim2real-behav-yaml-p-")
    json_param = "/" + ctx.unique_name("sim2real-behav-json-p-")

    # The YAML body must survive validation before any stack is created, and the
    # folded scalar must be re-flowed to a single space-joined line.
    summary = cf.get_template_summary(TemplateBody=_yaml_body(yaml_param))
    assert summary.get("Description") == _DESCRIPTION, (
        f"the YAML folded block scalar must be flowed to {_DESCRIPTION!r}, got "
        f"{summary.get('Description')!r}"
    )
    assert summary.get("ResourceTypes") == ["AWS::SSM::Parameter"], (
        f"GetTemplateSummary must project the YAML resource types, got "
        f"{summary.get('ResourceTypes')!r}"
    )
    yaml_params = {p["ParameterKey"]: p for p in summary.get("Parameters", [])}
    assert "Env" in yaml_params, f"YAML Parameters must be projected, got {list(yaml_params)}"
    assert yaml_params["Env"].get("DefaultValue") == "dev", yaml_params["Env"]
    assert yaml_params["Env"].get("ParameterConstraints", {}).get("AllowedValues") == [
        "dev", "prod"
    ], (
        f"the YAML flow-sequence AllowedValues must round-trip, got "
        f"{yaml_params['Env'].get('ParameterConstraints')!r}"
    )

    yaml_stack, yaml_obj = _deploy(ctx, cf, _yaml_body(yaml_param), yaml_param, "prod")
    json_stack, json_obj = _deploy(ctx, cf, _json_body(json_param), json_param, "prod")

    # The short-form intrinsics must have produced the real provisioned value.
    yaml_value = ssm.get_parameter(Name=yaml_param)["Parameter"]["Value"]
    json_value = ssm.get_parameter(Name=json_param)["Parameter"]["Value"]
    assert yaml_value == "prod-beta-gold", (
        f"!Join/!Ref/!Select/!Split/!If must resolve to 'prod-beta-gold', got {yaml_value!r}"
    )
    assert yaml_value == json_value, (
        f"YAML short form and JSON long form must resolve identically: "
        f"{yaml_value!r} vs {json_value!r}"
    )

    yaml_out = {o["OutputKey"]: o["OutputValue"] for o in yaml_obj.get("Outputs", [])}
    json_out = {o["OutputKey"]: o["OutputValue"] for o in json_obj.get("Outputs", [])}
    assert yaml_out.get("Combined") == f"{yaml_param}::{ctx.region}", (
        f"!Sub must interpolate both a resource Ref and a pseudo-parameter, got "
        f"{yaml_out.get('Combined')!r}"
    )
    assert yaml_out.get("ViaGetAtt") == "prod-beta-gold", (
        f"!GetAtt Param.Value must return the resolved property, got "
        f"{yaml_out.get('ViaGetAtt')!r}"
    )
    assert yaml_out.get("TierFlag") == "yes", (
        f"the short-form !Equals condition must be true for Env=prod, got "
        f"{yaml_out.get('TierFlag')!r}"
    )
    assert set(yaml_out) == set(json_out), (
        f"YAML and JSON twins must expose the same Outputs, {sorted(yaml_out)} vs {sorted(json_out)}"
    )
    assert yaml_out["TierFlag"] == json_out["TierFlag"], (
        f"TierFlag output must match between twins: {yaml_out['TierFlag']!r} vs "
        f"{json_out['TierFlag']!r}"
    )
    assert yaml_out["ViaGetAtt"] == json_out["ViaGetAtt"], (
        f"ViaGetAtt output must match between twins: {yaml_out['ViaGetAtt']!r} vs "
        f"{json_out['ViaGetAtt']!r}"
    )

    # GetTemplate must return the body CloudFormation actually stored; the stack
    # was created from YAML so the stored template must still parse as YAML, not
    # be silently rewritten into something the customer never submitted.
    stored = cf.get_template(StackName=yaml_stack)["TemplateBody"]
    stored_text = stored if isinstance(stored, str) else json.dumps(stored)
    assert "AWS::SSM::Parameter" in stored_text, stored_text[:300]
    assert json_stack != yaml_stack, (
        f"the YAML and JSON twins must be two distinct stacks, both got {yaml_stack!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
