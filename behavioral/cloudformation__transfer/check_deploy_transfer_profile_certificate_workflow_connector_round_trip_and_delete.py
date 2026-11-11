"""deploy-transfer-profile-certificate-workflow-connector-round-trip-and-delete."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-transfer-profile-certificate-workflow-connector-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "transfer"]

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


def _template(as2_id: str, cert_pem: str, description: str, trusted_host_key: str,
              url: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        # The per-run certificate private key never appears in the template or the Outputs.
        "Parameters": {"CertificatePrivateKey": {"Type": "String", "NoEcho": True}},
        "Resources": {
            "ConnectorSecret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {
                    "SecretString": json.dumps({"placeholder": "sim2real-connector-secret"}),
                },
            },
            "ConnectorRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": _TRUST,
                    "Policies": [{
                        "PolicyName": "connector-secret-access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": {"Ref": "ConnectorSecret"},
                            }],
                        },
                    }],
                },
            },
            "Certificate": {
                "Type": "AWS::Transfer::Certificate",
                "Properties": {
                    "Usage": "SIGNING",
                    "Certificate": cert_pem,
                    "PrivateKey": {"Ref": "CertificatePrivateKey"},
                    "Description": description,
                    "Tags": _tag("certificate"),
                },
            },
            "Profile": {
                "Type": "AWS::Transfer::Profile",
                "Properties": {
                    "As2Id": as2_id,
                    "ProfileType": "LOCAL",
                    "CertificateIds": [{"Ref": "Certificate"}],
                    "Tags": _tag("profile"),
                },
            },
            "Workflow": {
                "Type": "AWS::Transfer::Workflow",
                "Properties": {
                    "Description": description,
                    "Steps": [{
                        "Type": "DELETE",
                        "DeleteStepDetails": {"Name": "sim2real-delete-step"},
                    }],
                    "Tags": _tag("workflow"),
                },
            },
            "Connector": {
                "Type": "AWS::Transfer::Connector",
                "Properties": {
                    "AccessRole": {"Fn::GetAtt": ["ConnectorRole", "Arn"]},
                    "Url": url,
                    "SftpConfig": {
                        "UserSecretId": {"Ref": "ConnectorSecret"},
                        "TrustedHostKeys": [trusted_host_key],
                    },
                    "Tags": _tag("connector"),
                },
            },
        },
        "Outputs": {
            "CertificateRef": {"Value": {"Ref": "Certificate"}},
            "CertificateId": {"Value": {"Fn::GetAtt": ["Certificate", "CertificateId"]}},
            "CertificateArn": {"Value": {"Fn::GetAtt": ["Certificate", "Arn"]}},
            "ProfileRef": {"Value": {"Ref": "Profile"}},
            "ProfileId": {"Value": {"Fn::GetAtt": ["Profile", "ProfileId"]}},
            "ProfileArn": {"Value": {"Fn::GetAtt": ["Profile", "Arn"]}},
            "WorkflowRef": {"Value": {"Ref": "Workflow"}},
            "WorkflowId": {"Value": {"Fn::GetAtt": ["Workflow", "WorkflowId"]}},
            "WorkflowArn": {"Value": {"Fn::GetAtt": ["Workflow", "Arn"]}},
            "ConnectorRef": {"Value": {"Ref": "Connector"}},
            "ConnectorId": {"Value": {"Fn::GetAtt": ["Connector", "ConnectorId"]}},
            "ConnectorArn": {"Value": {"Fn::GetAtt": ["Connector", "Arn"]}},
            "ConnectorRoleArn": {"Value": {"Fn::GetAtt": ["ConnectorRole", "Arn"]}},
            "SecretArn": {"Value": {"Ref": "ConnectorSecret"}},
        },
    })


def _self_signed_cert_pem(common_name: str) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=10))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem


def _trusted_host_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH,
    ).decode("ascii")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Transfer::Certificate, Profile, Workflow and Connector are each real at
    Transfer: each Ref is the id an independent list holds, every declared property and tag reads
    back, and deleting the stack leaves every one answering its own ResourceNotFoundException."""
    transfer = ctx.client("transfer")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfntr2-")
    as2_id = ctx.unique_name("sim2real-as2")
    description = ctx.unique_name("sim2real-cfntr2-desc-")
    url = f"sftp://{ctx.unique_name('sftp-')}.sim2real-connector-test.invalid"
    cert_pem, key_pem = _self_signed_cert_pem("sim2real.invalid")
    trusted_host_key = _trusted_host_key()

    stack_id = create_stack(
        ctx, cfn, stack, _template(as2_id, cert_pem, description, trusted_host_key, url),
        Parameters=[{"ParameterKey": "CertificatePrivateKey", "ParameterValue": key_pem}],
        Capabilities=["CAPABILITY_IAM"],
    )
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    certificate_id, profile_id = outputs["CertificateId"], outputs["ProfileId"]
    workflow_id, connector_id = outputs["WorkflowId"], outputs["ConnectorId"]

    # Each Ref against an independent list filtered to a value only this run declares.
    got = {
        "Certificate": [c["CertificateId"] for c in paginate(
            transfer, "list_certificates", "Certificates") if c.get("Description") == description],
        "Profile": [p["ProfileId"] for p in paginate(transfer, "list_profiles", "Profiles")
                    if p["As2Id"] == as2_id],
        "Workflow": [w["WorkflowId"] for w in paginate(transfer, "list_workflows", "Workflows")
                     if w.get("Description") == description],
        "Connector": [c["ConnectorId"] for c in paginate(transfer, "list_connectors", "Connectors")
                      if c["Url"] == url],
    }
    want = {k: [outputs[f"{k}Ref"]] for k in got}
    assert got == want and want == {"Certificate": [certificate_id], "Profile": [profile_id],
                                    "Workflow": [workflow_id], "Connector": [connector_id]}, (
        f"listed ids {got!r}, Refs {want!r}"
    )

    certificate = transfer.describe_certificate(CertificateId=certificate_id)["Certificate"]
    got = (certificate["Arn"], certificate["Usage"], certificate.get("Description"),
           certificate["Certificate"].strip())
    assert got == (outputs["CertificateArn"], "SIGNING", description, cert_pem.strip()), (
        f"certificate reads {got!r}"
    )
    profile = transfer.describe_profile(ProfileId=profile_id)["Profile"]
    got = (profile["Arn"], profile["As2Id"], profile["ProfileType"], profile["CertificateIds"])
    assert got == (outputs["ProfileArn"], as2_id, "LOCAL", [certificate_id]), (
        f"profile reads {got!r}"
    )
    workflow = transfer.describe_workflow(WorkflowId=workflow_id)["Workflow"]
    got = (workflow["Arn"], workflow.get("Description"),
           [(s["Type"], s["DeleteStepDetails"]["Name"]) for s in workflow["Steps"]])
    want = (outputs["WorkflowArn"], description, [("DELETE", "sim2real-delete-step")])
    assert got == want, f"workflow reads {got!r}, expected {want!r}"
    connector = transfer.describe_connector(ConnectorId=connector_id)["Connector"]
    got = (connector["Arn"], connector["Url"], connector["AccessRole"],
           connector["SftpConfig"].get("UserSecretId"), connector["SftpConfig"]["TrustedHostKeys"])
    want = (outputs["ConnectorArn"], url, outputs["ConnectorRoleArn"], outputs["SecretArn"],
            [trusted_host_key])
    assert got == want, f"connector reads {got!r}, expected {want!r}"
    for key, arn in (("certificate", certificate["Arn"]), ("profile", profile["Arn"]),
                     ("workflow", workflow["Arn"]), ("connector", connector["Arn"])):
        got = _tags(transfer, arn)
        assert got == {"sim2real": stack, "sim2real-transfer": key}, f"{key} tags {got!r}"

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException", "Unknown certificate")
    expect_error(lambda: transfer.describe_certificate(CertificateId=certificate_id), *gone)
    gone = ("ResourceNotFoundException", "Unknown profile")
    expect_error(lambda: transfer.describe_profile(ProfileId=profile_id), *gone)
    gone = ("ResourceNotFoundException", "Unknown workflow")
    expect_error(lambda: transfer.describe_workflow(WorkflowId=workflow_id), *gone)
    gone = ("ResourceNotFoundException", "Unknown connector")
    expect_error(lambda: transfer.describe_connector(ConnectorId=connector_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
