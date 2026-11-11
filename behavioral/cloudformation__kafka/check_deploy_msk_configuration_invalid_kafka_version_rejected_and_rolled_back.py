"""deploy-msk-configuration-invalid-kafka-version-rejected-and-rolled-back."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "deploy-msk-configuration-invalid-kafka-version-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "kafka"]

_BAD_VERSION = "99.99.x"

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

# The handler message, after masking: the valid-version list changes as MSK adds versions.
_MESSAGE_RE = re.compile(
    r"\[ClientRequestToken: <token>\] "
    r"Unsupported KafkaVersion \[(?P<version>[^\]]+)\]\. "
    r"Valid values: \[(?P<valid_versions>[^\]]*)\] "
    r"\(Service: Kafka, Status Code: 400, Request ID: <id>\) "
    r"\(SDK Attempt Count: <n>\)"
)


def _template() -> str:
    return """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ConfigName:
    Type: String
  KafkaVersion:
    Type: String
Resources:
  MskConfig:
    Type: AWS::MSK::Configuration
    Properties:
      Name: !Ref ConfigName
      ServerProperties: |
        auto.create.topics.enable=true
      KafkaVersionsList:
        - !Ref KafkaVersion
Outputs:
  ConfigArn:
    Value: !Ref MskConfig
"""


def _active_kafka_version(kafka) -> str:
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    active = sorted(v["Version"] for v in versions if v.get("Status") == "ACTIVE")
    assert active, f"no ACTIVE Kafka version in ListKafkaVersions: {versions!r}"
    return active[0]


def _list_configurations(kafka) -> list:
    return paginate(kafka, "list_configurations", "Configurations")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AWS::MSK::Configuration naming an unsupported KafkaVersion fails with MSK's refusal.

    The configuration is never listed, while the same template with an active version deploys
    a configuration MSK lists and reads back with that version.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-msk-configuration.html
    """
    cfn = ctx.client("cloudformation")
    kafka = ctx.client("kafka")
    good_version = _active_kafka_version(kafka)
    bad_config_name = ctx.unique_name("sim2real-mskcfgbad-")
    good_config_name = ctx.unique_name("sim2real-mskcfggood-")

    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-mskcfggood-"), _template(),
                           Parameters=[
                               {"ParameterKey": "ConfigName", "ParameterValue": good_config_name},
                               {"ParameterKey": "KafkaVersion", "ParameterValue": good_version},
                           ])
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-mskcfgbad-"), _template(),
                          Parameters=[
                              {"ParameterKey": "ConfigName", "ParameterValue": bad_config_name},
                              {"ParameterKey": "KafkaVersion", "ParameterValue": _BAD_VERSION},
                          ])
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "MskConfig")
    message, code = handler_reason(reason, ctx.account, bad_config_name)
    match = _MESSAGE_RE.fullmatch(message)
    assert match is not None, f"handler message {message!r} does not have the refusal's shape"
    valid_versions = [v.strip() for v in match["valid_versions"].split(",") if v.strip()]
    got = (match["version"], _BAD_VERSION in valid_versions, good_version in valid_versions, code)
    assert got == (_BAD_VERSION, False, True, "InvalidRequest"), (
        f"the refusal reads {got!r}, valid versions {valid_versions!r}"
    )
    still_listed = [c for c in _list_configurations(kafka) if c["Name"] == bad_config_name]
    assert still_listed == [], f"ListConfigurations lists the rejected configuration: {still_listed!r}"

    # Positive control: same template, the one property given a VALID value.
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_arn = stack_outputs(cfn, good_id)["ConfigArn"]
    listed = [c["Arn"] for c in _list_configurations(kafka) if c["Name"] == good_config_name]
    assert listed == [good_arn], f"ListConfigurations lists {listed!r}; control Ref {good_arn!r}"
    control = kafka.describe_configuration(Arn=good_arn)
    got = (control["Name"], control["State"], control["KafkaVersions"])
    assert got == (good_config_name, "ACTIVE", [good_version]), f"the control reads {got!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
