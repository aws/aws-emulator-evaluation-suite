"""full-feature-template-resolves-every-declared-output."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "full-feature-template-resolves-every-declared-output"
GROUP = "stack_outputs"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 300.0
ENV_VALUE = "prod"
BASE64_PROBE = "sim2real-base64-probe"
JOIN_PARTS = ["alpha", "beta", "gamma"]
SPLIT_SOURCE = "one|two|three"
SPLIT_INDEX = 2

# Every key here must come back; DevOnly (Condition IsDev, false for ENV_VALUE == "prod") must not.
_EXPECTED_OUTPUTS = {
    "ParamEnv",
    "MappedSize",
    "CondFeature",
    "ProdOnly",
    "Joined",
    "SelectedFromSplit",
    "Base64Test",
    "PseudoStackId",
    "PseudoStackName",
    "PseudoAccountId",
    "PseudoRegion",
    "PseudoPartition",
    "PseudoUrlSuffix",
    "SubbedQueueName",
}
_CONDITIONAL_ABSENT = "DevOnly"

_URL_SUFFIXES = {"aws": "amazonaws.com", "aws-cn": "amazonaws.com.cn", "aws-us-gov": "amazonaws.com"}


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A template combining Parameters+AllowedValues, Mappings, Conditions, pseudo-parameters and nine
    intrinsics resolves EVERY declared Output, and omits only the one whose Condition is false.
    """
    cf = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    stack = ctx.unique_name("sim2real-cfn-alloutputs-")
    suffix = stack.rsplit("-", 1)[-1][:12]
    expected_queue_prefix = "sim2real-"

    cf.create_stack(
        StackName=stack,
        TemplateBody=_template(),
        Parameters=[
            {"ParameterKey": "Env", "ParameterValue": ENV_VALUE},
            {"ParameterKey": "Suffix", "ParameterValue": suffix},
        ],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    described = _poll_stack(cf, stack)
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r}: expected CREATE_COMPLETE, got {described['StackStatus']!r} "
        f"({described.get('StackStatusReason')!r})"
    )

    outputs = {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs") or []}

    # Set equality, not membership: an unresolved output that is silently dropped passes a
    # membership test.
    assert set(outputs) == _EXPECTED_OUTPUTS, (
        f"Outputs must be exactly the declared set. Missing "
        f"{sorted(_EXPECTED_OUTPUTS - set(outputs))!r}; unexpected "
        f"{sorted(set(outputs) - _EXPECTED_OUTPUTS)!r}. An output that cannot be resolved must fail "
        f"the stack, not disappear from a CREATE_COMPLETE response"
    )
    # The false-Condition output must be absent, so echoing every declared output does not pass.
    assert _CONDITIONAL_ABSENT not in outputs, (
        f"{_CONDITIONAL_ABSENT!r} carries Condition IsDev, which is false for Env={ENV_VALUE!r}, so it "
        f"must be omitted; got {outputs.get(_CONDITIONAL_ABSENT)!r}"
    )

    # Cross-checked against values derived outside the Outputs block, so a placeholder value fails.
    assert base64.b64decode(outputs["Base64Test"]).decode() == BASE64_PROBE, (
        f"Fn::Base64 must encode {BASE64_PROBE!r}; the output decoded to "
        f"{base64.b64decode(outputs['Base64Test'])!r}"
    )
    assert outputs["PseudoStackId"] == described["StackId"], (
        f"AWS::StackId must equal DescribeStacks.StackId {described['StackId']!r}, got "
        f"{outputs['PseudoStackId']!r}"
    )
    assert outputs["PseudoStackName"] == stack, (
        f"AWS::StackName must be the name this run chose, {stack!r}, got {outputs['PseudoStackName']!r}"
    )

    account, partition, region = _parse_stack_arn(described["StackId"])
    assert outputs["ParamEnv"] == ENV_VALUE, (
        f"Ref to a parameter with AllowedValues must be {ENV_VALUE!r}, got {outputs['ParamEnv']!r}"
    )
    assert outputs["MappedSize"] == "large", (
        f"FindInMap[EnvMap, {ENV_VALUE}, size] must be 'large', got {outputs['MappedSize']!r}"
    )
    assert outputs["CondFeature"] == "yes", (
        f"Fn::If on a true condition must take the true branch ('yes'), got {outputs['CondFeature']!r}"
    )
    assert outputs["ProdOnly"] == f"only-in-{ENV_VALUE}", (
        f"an Output whose Condition is true must carry its resolved value, got {outputs['ProdOnly']!r}"
    )
    assert outputs["Joined"] == "-".join(JOIN_PARTS), (
        f"Fn::Join must be {'-'.join(JOIN_PARTS)!r}, got {outputs['Joined']!r}"
    )
    assert outputs["SelectedFromSplit"] == SPLIT_SOURCE.split("|")[SPLIT_INDEX], (
        f"Fn::Select[{SPLIT_INDEX}] over Fn::Split must be "
        f"{SPLIT_SOURCE.split('|')[SPLIT_INDEX]!r}, got {outputs['SelectedFromSplit']!r}"
    )
    assert outputs["PseudoAccountId"] == account, (
        f"AWS::AccountId must match the account in the StackId ARN {account!r}, got "
        f"{outputs['PseudoAccountId']!r}"
    )
    assert outputs["PseudoRegion"] == region == ctx.region, (
        f"AWS::Region must be {ctx.region!r} and match the StackId ARN {region!r}, got "
        f"{outputs['PseudoRegion']!r}"
    )
    assert outputs["PseudoPartition"] == partition, (
        f"AWS::Partition must match the StackId ARN {partition!r}, got {outputs['PseudoPartition']!r}"
    )
    expected_suffix = _URL_SUFFIXES.get(partition)
    assert expected_suffix is not None, f"unexpected partition {partition!r} in {described['StackId']!r}"
    assert outputs["PseudoUrlSuffix"] == expected_suffix, (
        f"AWS::URLSuffix in partition {partition!r} must be {expected_suffix!r}, got "
        f"{outputs['PseudoUrlSuffix']!r}"
    )

    # The Fn::Sub-built name is asserted through SQS, not only through the stack's own output.
    expected_queue = f"{expected_queue_prefix}{account}-{region}-{suffix}"
    assert outputs["SubbedQueueName"] == expected_queue, (
        f"Fn::Sub over AWS::AccountId/AWS::Region must build {expected_queue!r}, got "
        f"{outputs['SubbedQueueName']!r}"
    )
    queue_url = sqs.get_queue_url(QueueName=expected_queue)["QueueUrl"]
    assert queue_url.endswith(f"/{expected_queue}"), (
        f"SQS must record the Fn::Sub-built name verbatim; GetQueueUrl returned {queue_url!r}"
    )

    # Conditions must gate resources too, not only outputs.
    provisioned = {
        r["LogicalResourceId"]: r["ResourceStatus"]
        for r in cf.describe_stack_resources(StackName=stack)["StackResources"]
    }
    assert set(provisioned) == {"Queue", "ProdQueue"}, (
        f"Env={ENV_VALUE!r} makes IsProd true, so both queues must exist and nothing else; got "
        f"{sorted(provisioned)!r}"
    )
    assert set(provisioned.values()) == {"CREATE_COMPLETE"}, (
        f"every resource in a CREATE_COMPLETE stack must itself be CREATE_COMPLETE, got {provisioned!r}"
    )


def _template() -> str:
    """Parameters+AllowedValues, Mappings, Conditions, pseudo-parameters, nine intrinsics and an
    Fn::Sub-built resource name in ONE template, since dropped outputs only show in the combination;
    15 declared Outputs, one conditionally absent."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "SimParity full-feature output-resolution probe",
            "Parameters": {
                "Env": {"Type": "String", "AllowedValues": ["dev", "prod"], "Default": "dev"},
                "Suffix": {"Type": "String"},
            },
            "Mappings": {"EnvMap": {"dev": {"size": "small"}, "prod": {"size": "large"}}},
            "Conditions": {
                "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
                "IsDev": {"Fn::Equals": [{"Ref": "Env"}, "dev"]},
            },
            "Resources": {
                "Queue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": {
                            "Fn::Sub": "sim2real-${AWS::AccountId}-${AWS::Region}-${Suffix}"
                        },
                        "VisibilityTimeout": 45,
                    },
                },
                # Condition-gated, so Conditions affect provisioning and not only outputs.
                "ProdQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "IsProd",
                    "Properties": {
                        "QueueName": {"Fn::Sub": "sim2real-prod-${AWS::Region}-${Suffix}"},
                    },
                },
            },
            "Outputs": {
                "ParamEnv": {"Value": {"Ref": "Env"}},
                "MappedSize": {"Value": {"Fn::FindInMap": ["EnvMap", {"Ref": "Env"}, "size"]}},
                "CondFeature": {"Value": {"Fn::If": ["IsProd", "yes", "no"]}},
                "ProdOnly": {"Condition": "IsProd", "Value": {"Fn::Sub": "only-in-${Env}"}},
                "DevOnly": {"Condition": "IsDev", "Value": {"Fn::Sub": "only-in-${Env}"}},
                "Joined": {"Value": {"Fn::Join": ["-", JOIN_PARTS]}},
                "SelectedFromSplit": {
                    "Value": {
                        "Fn::Select": [str(SPLIT_INDEX), {"Fn::Split": ["|", SPLIT_SOURCE]}]
                    }
                },
                "Base64Test": {"Value": {"Fn::Base64": BASE64_PROBE}},
                "PseudoStackId": {"Value": {"Ref": "AWS::StackId"}},
                "PseudoStackName": {"Value": {"Ref": "AWS::StackName"}},
                "PseudoAccountId": {"Value": {"Ref": "AWS::AccountId"}},
                "PseudoRegion": {"Value": {"Ref": "AWS::Region"}},
                "PseudoPartition": {"Value": {"Ref": "AWS::Partition"}},
                "PseudoUrlSuffix": {"Value": {"Ref": "AWS::URLSuffix"}},
                "SubbedQueueName": {"Value": {"Fn::GetAtt": ["Queue", "QueueName"]}},
            },
        }
    )


def _poll_stack(cf, stack_name: str) -> dict:
    """Poll DescribeStacks to a create-terminal state and return the WHOLE stack dict, so the
    Outputs asserted on and the StackId they are cross-checked against come from one read."""
    terminal = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_name)["Stacks"][0]
        if last["StackStatus"] in terminal:
            return last
        time.sleep(4.0)
    last_status = last.get("StackStatus") if last else None
    raise AssertionError(
        f"stack {stack_name!r} did not reach a create-terminal state within {STACK_TIMEOUT_S}s "
        f"(last={last_status!r})"
    )


def _parse_stack_arn(stack_id: str) -> tuple[str, str, str]:
    """(account, partition, region) out of arn:<partition>:cloudformation:<region>:<account>:stack/..."""
    parts = stack_id.split(":")
    assert len(parts) >= 6 and parts[0] == "arn", f"malformed StackId {stack_id!r}"
    assert parts[2] == "cloudformation", f"StackId names the wrong service: {stack_id!r}"
    return parts[4], parts[1], parts[3]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
