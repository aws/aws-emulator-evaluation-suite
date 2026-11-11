"""deploy-amazonmq-broker-engine-version-rejected-then-config-association-verified."""
from __future__ import annotations

import json
import re
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-amazonmq-broker-engine-version-rejected-then-config-association-verified"
GROUP = "deploy"
SERVICES = ["cloudformation", "mq"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_VPC_CIDR = "10.84.0.0/16"
_SUBNET_CIDR = "10.84.1.0/24"
_BAD_VERSION = "99.99"
#: A single-instance mq.t3.micro ActiveMQ broker, the smallest MQ offers, takes minutes to create.
_BROKER_CREATE_S = 1500.0

#: base64 of a minimal, well-formed ActiveMQ configuration document; AWS::AmazonMQ::Configuration
#: requires ``Data`` at creation even though its own schema does not mark it ``required``.
_CONFIG_DATA = (
    "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9InllcyI/Pjxicm9rZXIgeG1sbnM9"
    "Imh0dHA6Ly9hY3RpdmVtcS5hcGFjaGUub3JnL3NjaGVtYS9jb3JlIj48L2Jyb2tlcj4="
)

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _template(broker_name: str, config_name: str, engine_version: str) -> str:
    """VPC, subnet, security group, configuration, broker and association; the admin password is
    a NoEcho parameter generated per run."""
    t = [{"Key": "sim2real-mq", "Value": broker_name}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"AdminPassword": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                                "Tags": t},
            },
            "Sg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {"GroupDescription": "sim2real-amazonmq-broker-sg",
                                "VpcId": {"Ref": "Vpc"}, "Tags": t},
            },
            "Configuration": {
                "Type": "AWS::AmazonMQ::Configuration",
                "Properties": {"Name": config_name, "EngineType": "ACTIVEMQ",
                                "Data": _CONFIG_DATA, "Tags": t},
            },
            "Broker": {
                "Type": "AWS::AmazonMQ::Broker",
                "Properties": {
                    "BrokerName": broker_name,
                    "EngineType": "ACTIVEMQ",
                    "EngineVersion": engine_version,
                    "DeploymentMode": "SINGLE_INSTANCE",
                    "HostInstanceType": "mq.t3.micro",
                    "PubliclyAccessible": False,
                    "SubnetIds": [{"Ref": "Subnet"}],
                    "SecurityGroups": [{"Fn::GetAtt": ["Sg", "GroupId"]}],
                    "Users": [{"Username": "admin", "Password": {"Ref": "AdminPassword"}}],
                    "Tags": t,
                },
            },
            "ConfigAssoc": {
                "Type": "AWS::AmazonMQ::ConfigurationAssociation",
                "Properties": {
                    "Broker": {"Ref": "Broker"},
                    "Configuration": {
                        "Id": {"Ref": "Configuration"},
                        "Revision": {"Fn::GetAtt": ["Configuration", "Revision"]},
                    },
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "SgId": {"Value": {"Fn::GetAtt": ["Sg", "GroupId"]}},
            "ConfigurationId": {"Value": {"Ref": "Configuration"}},
            "ConfigurationArn": {"Value": {"Fn::GetAtt": ["Configuration", "Arn"]}},
            "ConfigurationRevision": {"Value": {"Fn::GetAtt": ["Configuration", "Revision"]}},
            "BrokerId": {"Value": {"Ref": "Broker"}},
            "BrokerArn": {"Value": {"Fn::GetAtt": ["Broker", "Arn"]}},
            "BrokerConfigurationId": {"Value": {"Fn::GetAtt": ["Broker", "ConfigurationId"]}},
            "BrokerConfigurationRevision": {"Value": {"Fn::GetAtt": ["Broker", "ConfigurationRevision"]}},
            "ConfigAssocId": {"Value": {"Ref": "ConfigAssoc"}},
        },
    })


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_broker_stack(cfn, stack_id):
    """``delete_stack``; on DELETE_FAILED delete again retaining only ``ConfigAssoc``, then raise.

    The association is no MQ object of its own, so retaining it leaves nothing behind, while the
    broker, its configuration and network are always deleted even when the association's own
    delete fails.
    """
    try:
        delete_stack(cfn, stack_id)
    except AssertionError:
        if cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] == "DELETE_FAILED":
            cfn.delete_stack(StackName=stack_id, RetainResources=["ConfigAssoc"])
            wait_stack(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _DELETE_BUDGET_S)
        raise


def _password():
    return [{"ParameterKey": "AdminPassword", "ParameterValue": secrets.token_urlsafe(16)}]


def _brokers(mq, name):
    return [b for b in paginate(mq, "list_brokers", "BrokerSummaries") if b["BrokerName"] == name]


def _own_tags(tags_):
    """A resource's tags without CloudFormation's aws:* system tags."""
    return {k: v for k, v in tags_.items() if not k.startswith("aws:")}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """An AWS::AmazonMQ::Broker with an EngineVersion MQ does not offer is refused by the handler
    with MQ's exact error and no broker exists, while the same template with an offered version
    deploys a broker MQ reads back, its ConfigurationAssociation applied.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-amazonmq-broker.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-amazonmq-configurationassociation.html
    """
    cfn = ctx.client("cloudformation")
    mq = ctx.client("mq")

    versions = sorted(
        (v["Name"] for v in mq.describe_broker_engine_types(EngineType="ACTIVEMQ")
         ["BrokerEngineTypes"][0]["EngineVersions"]),
        reverse=True,
    )
    assert versions, "describe_broker_engine_types(ACTIVEMQ) returned no engine versions"
    good_version = versions[0]
    assert _BAD_VERSION not in versions, f"{_BAD_VERSION!r} is unexpectedly a real ACTIVEMQ version"

    # The one change: an EngineVersion MQ does not offer for ACTIVEMQ. The handler refuses it
    # at once, so only the control below pays a broker create.
    bad_broker_name = ctx.unique_name("sim2real-mqbkbad-")
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-mqstackbad-"),
                          _template(bad_broker_name, ctx.unique_name("sim2real-mqcfgbad-"),
                                    _BAD_VERSION),
                          Parameters=_password())
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "Broker")
    match = _REASON.match(reason or "")
    assert match is not None, f"CREATE_FAILED reason is not a resource-handler message: {reason!r}"
    got_error = (match["message"], match["service"], match["status"], match["handler"])
    want_error = (
        f"Broker engine version [{_BAD_VERSION}] is invalid for broker engine type [ACTIVEMQ]. "
        f"Valid values: [{', '.join(versions)}].",
        "Mq", "400", "InvalidRequest",
    )
    assert got_error == want_error, f"CREATE_FAILED reason {got_error!r}, expected {want_error!r}"
    # Rollback absence through MQ, by the name the broker would have, before any delete.
    assert _brokers(mq, bad_broker_name) == [], f"ListBrokers lists {bad_broker_name!r}"

    # Positive control: the same template with the newest version MQ offers.
    good_broker_name = ctx.unique_name("sim2real-mqbkgood-")
    good_config_name = ctx.unique_name("sim2real-mqcfggood-")
    good_stack = ctx.unique_name("sim2real-mqstackgood-")
    # MQ creates a default configuration for a broker that has none at creation; the association
    # then moves the broker onto the template's, leaving the default with no stack owning it.
    # Deleting the association moves the broker back onto the default, so the default's delete
    # is registered BEFORE the stack: cleanups run LIFO, and it runs after the stack is gone.
    defaults = []

    def delete_defaults():
        for cfg_id in defaults:
            _teardown(lambda cfg_id=cfg_id: mq.delete_configuration(ConfigurationId=cfg_id),
                      "NotFoundException")()

    ctx.on_cleanup(delete_defaults)
    good_id = create_stack(ctx, cfn, good_stack,
                           _template(good_broker_name, good_config_name, good_version),
                           Parameters=_password())
    ctx.on_cleanup(lambda: _delete_broker_stack(cfn, good_id))
    status = wait_stack(cfn, good_id, timeout_s=_BROKER_CREATE_S)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    outs = stack_outputs(cfn, good_id)
    listed = _brokers(mq, good_broker_name)
    assert [b["BrokerId"] for b in listed] == [outs["BrokerId"]], (
        f"ListBrokers entries named {good_broker_name!r}: {listed!r}, Ref {outs['BrokerId']!r}"
    )
    broker = mq.describe_broker(BrokerId=listed[0]["BrokerId"])

    defaults.extend(h["Id"] for h in broker["Configurations"].get("History", [])
                    if h["Id"] != outs["ConfigurationId"])

    got = {k: broker.get(k) for k in ("BrokerArn", "BrokerName", "EngineType", "EngineVersion",
                                      "DeploymentMode", "HostInstanceType",
                                      "PubliclyAccessible", "SubnetIds", "SecurityGroups")}
    want = {"BrokerArn": outs["BrokerArn"], "BrokerName": good_broker_name,
            "EngineType": "ActiveMQ", "EngineVersion": good_version,
            "DeploymentMode": "SINGLE_INSTANCE", "HostInstanceType": "mq.t3.micro",
            "PubliclyAccessible": False, "SubnetIds": [outs["SubnetId"]],
            "SecurityGroups": [outs["SgId"]]}
    assert got == want, f"DescribeBroker {got!r}, expected {want!r}"
    assert [u["Username"] for u in broker["Users"]] == ["admin"], f"users {broker['Users']!r}"
    assert _own_tags(broker.get("Tags", {})) == {"sim2real": good_stack,
                                                 "sim2real-mq": good_broker_name}, (
        f"broker tags {broker.get('Tags')!r}"
    )

    current = broker["Configurations"]["Current"]
    got = (current["Id"], str(current["Revision"]))
    assert got == (outs["ConfigurationId"], outs["ConfigurationRevision"]), (
        f"the broker's current configuration {got!r}, the association applied "
        f"{(outs['ConfigurationId'], outs['ConfigurationRevision'])!r}"
    )
    assert (outs["BrokerConfigurationId"], outs["BrokerConfigurationRevision"]) == got, (
        f"GetAtt Broker.ConfigurationId/Revision "
        f"{(outs['BrokerConfigurationId'], outs['BrokerConfigurationRevision'])!r} != {got!r}"
    )
    config = mq.describe_configuration(ConfigurationId=outs["ConfigurationId"])
    got = (config["Arn"], config["Name"], config["EngineType"], _own_tags(config.get("Tags", {})))
    assert got == (outs["ConfigurationArn"], good_config_name, "ActiveMQ",
                   {"sim2real": good_stack, "sim2real-mq": good_broker_name}), (
        f"DescribeConfiguration (arn, name, engine, tags) {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
