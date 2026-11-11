"""deploy-transfer-as2-server-and-agreement-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-transfer-as2-server-and-agreement-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "transfer"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "transfer.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def _tag(value):
    """A template tag the propagated stack tag (key sim2real) never carries."""
    return [{"Key": "sim2real-transfer", "Value": value}]


def _tags(transfer, arn):
    return {t["Key"]: t["Value"] for t in paginate(transfer, "list_tags_for_resource", "Tags",
                                                   Arn=arn)
            if not t["Key"].startswith("aws:")}


_VPC_CIDR = "10.91.0.0/16"
_SUBNET_CIDR = "10.91.1.0/24"


def _network(port):
    """A check-owned VPC, subnet and security group admitting ``port`` from inside the VPC only."""
    return {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "Subnet": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
            },
        },
        "ServerSecurityGroup": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "sim2real Transfer server endpoint, VPC-internal only",
                "VpcId": {"Ref": "Vpc"},
                "SecurityGroupIngress": [{
                    "IpProtocol": "tcp", "FromPort": port, "ToPort": port, "CidrIp": _VPC_CIDR,
                }],
            },
        },
    }


_NETWORK_OUTPUTS = {
    "VpcId": {"Value": {"Ref": "Vpc"}},
    "SubnetId": {"Value": {"Ref": "Subnet"}},
    "SecurityGroupId": {"Value": {"Ref": "ServerSecurityGroup"}},
}


def _endpoint_details(server):
    details = server.get("EndpointDetails", {})
    return (details.get("VpcId"), details.get("SubnetIds"), details.get("SecurityGroupIds"))


def _template(local_as2_id: str, partner_as2_id: str, with_agreement=True) -> str:
    resources = {
        "As2Bucket": {"Type": "AWS::S3::Bucket"},
        "As2Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": _TRUST,
                "Policies": [{
                    "PolicyName": "as2-bucket-access",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": ["s3:ListBucket", "s3:GetObject", "s3:PutObject"],
                            "Resource": [
                                {"Fn::GetAtt": ["As2Bucket", "Arn"]},
                                {"Fn::Join": ["", [{"Fn::GetAtt": ["As2Bucket", "Arn"]}, "/*"]]},
                            ],
                        }],
                    },
                }],
            },
        },
        **_network(5080),
        "LocalProfile": {
            "Type": "AWS::Transfer::Profile",
            "Properties": {"As2Id": local_as2_id, "ProfileType": "LOCAL",
                           "Tags": _tag("local-profile")},
        },
        "PartnerProfile": {
            "Type": "AWS::Transfer::Profile",
            "Properties": {"As2Id": partner_as2_id, "ProfileType": "PARTNER",
                           "Tags": _tag("partner-profile")},
        },
        "Server": {
            "Type": "AWS::Transfer::Server",
            "Properties": {
                "Protocols": ["AS2"],
                "ProtocolDetails": {"As2Transports": ["HTTP"]},
                "EndpointType": "VPC",
                "EndpointDetails": {
                    "VpcId": {"Ref": "Vpc"},
                    "SubnetIds": [{"Ref": "Subnet"}],
                    "SecurityGroupIds": [{"Ref": "ServerSecurityGroup"}],
                },
                "Tags": _tag("server"),
            },
        },
    }
    outputs = {
        **_NETWORK_OUTPUTS,
        "ServerId": {"Value": {"Fn::GetAtt": ["Server", "ServerId"]}},
        "ServerArn": {"Value": {"Fn::GetAtt": ["Server", "Arn"]}},
        "LocalProfileId": {"Value": {"Fn::GetAtt": ["LocalProfile", "ProfileId"]}},
        "LocalProfileArn": {"Value": {"Fn::GetAtt": ["LocalProfile", "Arn"]}},
        "PartnerProfileId": {"Value": {"Fn::GetAtt": ["PartnerProfile", "ProfileId"]}},
        "PartnerProfileArn": {"Value": {"Fn::GetAtt": ["PartnerProfile", "Arn"]}},
        "RoleArn": {"Value": {"Fn::GetAtt": ["As2Role", "Arn"]}},
        "BucketName": {"Value": {"Ref": "As2Bucket"}},
    }
    if with_agreement:
        resources["Agreement"] = {
            "Type": "AWS::Transfer::Agreement",
            "Properties": {
                "ServerId": {"Fn::GetAtt": ["Server", "ServerId"]},
                "LocalProfileId": {"Fn::GetAtt": ["LocalProfile", "ProfileId"]},
                "PartnerProfileId": {"Fn::GetAtt": ["PartnerProfile", "ProfileId"]},
                "AccessRole": {"Fn::GetAtt": ["As2Role", "Arn"]},
                "BaseDirectory": {"Fn::Join": ["", ["/", {"Ref": "As2Bucket"}, "/as2-inbox"]]},
                "Tags": _tag("agreement"),
            },
        }
        outputs.update({
            "AgreementRef": {"Value": {"Ref": "Agreement"}},
            "AgreementId": {"Value": {"Fn::GetAtt": ["Agreement", "AgreementId"]}},
            "AgreementArn": {"Value": {"Fn::GetAtt": ["Agreement", "Arn"]}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AS2 Transfer Server in a check-owned VPC, two Profiles and an Agreement read
    back through Transfer (ids, properties, tags); an update dropping the agreement removes it while
    the server answers, and the stack delete leaves the server and profiles not-found."""
    transfer = ctx.client("transfer")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfnas2-")
    local_as2_id = ctx.unique_name("sim2real-local-as2")
    partner_as2_id = ctx.unique_name("sim2real-partner-as2")

    stack_id = create_stack(ctx, cfn, stack, _template(local_as2_id, partner_as2_id),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=900.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    server_id, agreement_id = outputs["ServerId"], outputs["AgreementId"]

    listed = [s["Arn"] for s in paginate(transfer, "list_servers", "Servers")
              if s["ServerId"] == server_id]
    assert listed == [outputs["ServerArn"]], f"ListServers {listed!r} for {server_id!r}"
    server = transfer.describe_server(ServerId=server_id)["Server"]
    got = (server["Protocols"], server["EndpointType"], server["ProtocolDetails"]["As2Transports"],
           _endpoint_details(server))
    # DescribeServer echoes VpcId and SubnetIds; AWS returns no SecurityGroupIds member for this
    # VPC server, so the templated group is not readable here and reads None.
    want = (["AS2"], "VPC", ["HTTP"],
            (outputs["VpcId"], [outputs["SubnetId"]], None))
    assert got == want, f"server (protocols, endpoint, transports, details) {got!r} != {want!r}"
    got = _tags(transfer, outputs["ServerArn"])
    assert got == {"sim2real": stack, "sim2real-transfer": "server"}, f"server tags {got!r}"

    for key, as2_id, ptype in (("LocalProfile", local_as2_id, "LOCAL"),
                               ("PartnerProfile", partner_as2_id, "PARTNER")):
        listed = [p["ProfileId"] for p in paginate(transfer, "list_profiles", "Profiles",
                                                   ProfileType=ptype) if p["As2Id"] == as2_id]
        assert listed == [outputs[f"{key}Id"]], f"ListProfiles {listed!r} for {key}"
        profile = transfer.describe_profile(ProfileId=outputs[f"{key}Id"])["Profile"]
        got = (profile["As2Id"], profile["ProfileType"], profile["Arn"])
        assert got == (as2_id, ptype, outputs[f"{key}Arn"]), f"{key} reads {got!r}"
        got = _tags(transfer, profile["Arn"])
        want = {"sim2real": stack, "sim2real-transfer": key.replace("Profile", "").lower()
                + "-profile"}
        assert got == want, f"{key} tags {got!r}, expected {want!r}"

    listed = [a["AgreementId"] for a in paginate(transfer, "list_agreements", "Agreements",
                                                 ServerId=server_id)]
    assert listed == [agreement_id], f"ListAgreements {listed!r} for {agreement_id!r}"
    assert outputs["AgreementRef"] == f"{agreement_id}|{server_id}", (
        f"Ref Agreement {outputs['AgreementRef']!r} is not 'AgreementId|ServerId'"
    )
    agreement = transfer.describe_agreement(AgreementId=agreement_id, ServerId=server_id)
    agreement = agreement["Agreement"]
    got = {k: agreement.get(k) for k in ("Arn", "ServerId", "LocalProfileId", "PartnerProfileId",
                                         "AccessRole", "BaseDirectory")}
    want = {"Arn": outputs["AgreementArn"], "ServerId": server_id,
            "LocalProfileId": outputs["LocalProfileId"],
            "PartnerProfileId": outputs["PartnerProfileId"], "AccessRole": outputs["RoleArn"],
            "BaseDirectory": f"/{outputs['BucketName']}/as2-inbox"}
    assert got == want, f"agreement reads {got!r}, expected {want!r}"
    got = _tags(transfer, outputs["AgreementArn"])
    assert got == {"sim2real": stack, "sim2real-transfer": "agreement"}, f"agreement tags {got!r}"

    # Child first: the update drops the agreement; its own NotFound while the server answers.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(local_as2_id, partner_as2_id, with_agreement=False),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=900.0)
    assert status == "UPDATE_COMPLETE", f"agreement-dropping update ended {status!r}"
    gone = ("ResourceNotFoundException", "Unknown agreement")
    expect_error(lambda: transfer.describe_agreement(AgreementId=agreement_id,
                                                     ServerId=server_id), *gone)
    after_arn = transfer.describe_server(ServerId=server_id)["Server"]["Arn"]
    assert after_arn == outputs["ServerArn"], (
        f"server after the update reads Arn {after_arn!r}, expected {outputs['ServerArn']!r}"
    )

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException", "Unknown server")
    expect_error(lambda: transfer.describe_server(ServerId=server_id), *gone)
    gone = ("ResourceNotFoundException", "Unknown profile")
    for key in ("LocalProfileId", "PartnerProfileId"):
        expect_error(lambda key=key: transfer.describe_profile(ProfileId=outputs[key]), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
