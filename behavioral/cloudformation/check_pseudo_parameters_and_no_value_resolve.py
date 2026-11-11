"""pseudo-parameters-and-no-value-resolve."""
from __future__ import annotations

import base64
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pseudo-parameters-and-no-value-resolve"
GROUP = 'intrinsic_functions'
SERVICES = ['cloudformation']

# ===== helpers =====
_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}
_AZ_RE = re.compile(r"^[a-z0-9-]+[a-z]$")


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


def _ssm_description(ssm, name):
    """Return the SSM parameter's Description, or None when it has none."""
    page = ssm.describe_parameters(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    )["Parameters"]
    assert page, f"parameter {name} not found via DescribeParameters"
    return page[0].get("Description")


# ===== end helpers =====


def _template(param_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "WantDescription": {"Type": "String", "Default": "false",
                                "AllowedValues": ["true", "false"]},
        },
        "Conditions": {
            "HasDescription": {"Fn::Equals": [{"Ref": "WantDescription"}, "true"]},
        },
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": param_name,
                    "Type": "String",
                    "Value": "pseudo",
                    # Fn::If -> AWS::NoValue must ELIDE the property entirely.
                    "Description": {"Fn::If": [
                        "HasDescription", "described", {"Ref": "AWS::NoValue"},
                    ]},
                },
            },
        },
        "Outputs": {
            "Account": {"Value": {"Ref": "AWS::AccountId"}},
            "Partition": {"Value": {"Ref": "AWS::Partition"}},
            "Region": {"Value": {"Ref": "AWS::Region"}},
            "UrlSuffix": {"Value": {"Ref": "AWS::URLSuffix"}},
            "StackId": {"Value": {"Ref": "AWS::StackId"}},
            "StackName": {"Value": {"Ref": "AWS::StackName"}},
            "Azs": {"Value": {"Fn::Join": [",", {"Fn::GetAZs": ""}]}},
            "Encoded": {"Value": {"Fn::Base64": "sim2real"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c5", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Pseudo-parameters resolve consistently with the stack's own ARN, Fn::GetAZs returns the region's
    real zones, Fn::Base64 really encodes, and Fn::If -> AWS::NoValue removes the property (not the
    literal string), which reappears when the condition flips.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")

    stack = ctx.unique_name("sim2real-behav-pseudo-")
    param_name = "/" + ctx.unique_name("sim2real-behav-pseudo-p-")

    cf.create_stack(StackName=stack, TemplateBody=_template(param_name))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )

    out = {o["OutputKey"]: o["OutputValue"] for o in created.get("Outputs", [])}
    stack_arn = created["StackId"]
    arn_parts = stack_arn.split(":")
    assert len(arn_parts) >= 6 and arn_parts[0] == "arn", f"malformed StackId {stack_arn!r}"
    partition, service, region, account = arn_parts[1], arn_parts[2], arn_parts[3], arn_parts[4]
    assert service == "cloudformation", stack_arn

    # Every pseudo-parameter must agree with the stack's own identity.
    assert out.get("StackId") == stack_arn, (
        f"AWS::StackId must equal DescribeStacks.StackId {stack_arn!r}, got {out.get('StackId')!r}"
    )
    assert out.get("StackName") == stack, (
        f"AWS::StackName must be {stack!r}, got {out.get('StackName')!r}"
    )
    assert out.get("Region") == region == ctx.region, (
        f"AWS::Region must be {ctx.region!r} and match the ARN {region!r}, got "
        f"{out.get('Region')!r}"
    )
    assert out.get("Account") == account, (
        f"AWS::AccountId must equal the ARN account {account!r}, got {out.get('Account')!r}"
    )
    assert re.fullmatch(r"\d{12}", out.get("Account") or ""), (
        f"AWS::AccountId must be a 12-digit account id, got {out.get('Account')!r}"
    )
    assert out.get("Partition") == partition, (
        f"AWS::Partition must equal the ARN partition {partition!r}, got "
        f"{out.get('Partition')!r}"
    )
    # Partition -> URLSuffix is AWS reference data, not a free-form string.
    expected_suffix = {
        "aws": "amazonaws.com",
        "aws-cn": "amazonaws.com.cn",
        "aws-us-gov": "amazonaws.com",
    }.get(partition)
    assert expected_suffix is not None, f"unexpected partition {partition!r}"
    assert out.get("UrlSuffix") == expected_suffix, (
        f"AWS::URLSuffix in partition {partition!r} must be {expected_suffix!r}, got "
        f"{out.get('UrlSuffix')!r}"
    )

    # Fn::GetAZs must be the region's real AZ list.
    azs = [a for a in (out.get("Azs") or "").split(",") if a]
    assert len(azs) >= 2, f"Fn::GetAZs must return at least two AZs, got {azs}"
    for az in azs:
        assert az.startswith(ctx.region), (
            f"AZ {az!r} must be inside the caller's region {ctx.region!r} (got {azs})"
        )
        assert _AZ_RE.fullmatch(az), f"AZ {az!r} is not a well-formed zone name (got {azs})"
    assert len(set(azs)) == len(azs), f"Fn::GetAZs must not repeat zones: {azs}"

    # Fn::GetAZs is AWS reference data, not a plausible-looking string: it must match
    # EC2's own available-zone list for the region, independently queried.
    real_azs = {
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}],
        )["AvailabilityZones"]
    }
    assert set(azs) == real_azs, (
        f"Fn::GetAZs {sorted(azs)} must equal EC2's available zones for {ctx.region!r}: "
        f"{sorted(real_azs)}"
    )

    assert out.get("Encoded") == base64.b64encode(b"sim2real").decode(), (
        f"Fn::Base64 must be a real base64 encoding, got {out.get('Encoded')!r}"
    )

    # AWS::NoValue must have ELIDED Description, not written it as a string.
    description = _ssm_description(ssm, param_name)
    assert description in (None, ""), (
        f"Fn::If -> AWS::NoValue must remove the Description property, found {description!r}"
    )

    # Flip the condition: the property must now be present with the real value.
    cf.update_stack(
        StackName=stack, TemplateBody=_template(param_name),
        Parameters=[{"ParameterKey": "WantDescription", "ParameterValue": "true"}],
    )
    updated = _wait_terminal(cf, stack)
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE, got {updated['StackStatus']!r}: "
        f"{updated.get('StackStatusReason')!r}"
    )
    assert _ssm_description(ssm, param_name) == "described", (
        "flipping the condition must set the previously elided property to the real value"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
