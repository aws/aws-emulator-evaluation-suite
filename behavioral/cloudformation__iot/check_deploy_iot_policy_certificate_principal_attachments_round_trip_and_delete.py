"""deploy-iot-policy-certificate-principal-attachments-round-trip-and-delete."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-iot-policy-certificate-principal-attachments-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot"]

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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


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

_POLICY_GONE = ("ResourceNotFoundException", "Policy default version not found")
_THING_GONE = ("ResourceNotFoundException", "Thing <account>:<name> not found.")
_POLICY_ACTION = "iot:Connect"
_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": [_POLICY_ACTION], "Resource": ["*"]}],
}
_DETACH_DEADLINE_S = 120.0


def _openssl(*args: str) -> str:
    return subprocess.run(["openssl", *args], check=True, capture_output=True, text=True,
                          timeout=60).stdout


def _generate_csr(common_name: str) -> tuple[str, str]:
    """A fresh key's CSR and its public key PEM, so no run reuses another's key material."""
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "device.key")
        csr = os.path.join(d, "device.csr")
        _openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr,
                 "-subj", f"/CN={common_name}")
        with open(csr) as f:
            csr_pem = f.read()
        return csr_pem, _openssl("req", "-in", csr, "-noout", "-pubkey")


def _cert_public_key(cert_pem: str) -> str:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "cert.pem")
        with open(path, "w") as f:
            f.write(cert_pem)
        return _openssl("x509", "-in", path, "-noout", "-pubkey")


def _template(policy_name: str, thing_name: str, csr: str, *, attachments: bool) -> str:
    resources: dict = {
        "Policy": {
            "Type": "AWS::IoT::Policy",
            "Properties": {"PolicyName": policy_name, "PolicyDocument": _POLICY_DOCUMENT},
        },
        "Thing": {"Type": "AWS::IoT::Thing", "Properties": {"ThingName": thing_name}},
        "Certificate": {
            "Type": "AWS::IoT::Certificate",
            "Properties": {"CertificateSigningRequest": csr, "Status": "ACTIVE"},
        },
    }
    if attachments:
        resources["PolicyAttachment"] = {
            "Type": "AWS::IoT::PolicyPrincipalAttachment",
            "DependsOn": ["Policy", "Certificate"],
            "Properties": {
                "PolicyName": {"Ref": "Policy"},
                "Principal": {"Fn::GetAtt": ["Certificate", "Arn"]},
            },
        }
        resources["ThingAttachment"] = {
            "Type": "AWS::IoT::ThingPrincipalAttachment",
            "DependsOn": ["Thing", "Certificate"],
            "Properties": {
                "ThingName": {"Ref": "Thing"},
                "Principal": {"Fn::GetAtt": ["Certificate", "Arn"]},
            },
        }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "PolicyRef": {"Value": {"Ref": "Policy"}},
            "PolicyArn": {"Value": {"Fn::GetAtt": ["Policy", "Arn"]}},
            "ThingRef": {"Value": {"Ref": "Thing"}},
            "ThingArn": {"Value": {"Fn::GetAtt": ["Thing", "Arn"]}},
            "CertificateRef": {"Value": {"Ref": "Certificate"}},
            "CertificateArn": {"Value": {"Fn::GetAtt": ["Certificate", "Arn"]}},
        },
    })


def _refusal(fn, account, *names):
    """(Error.Code, Error.Message masked) of the ClientError fn() raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), masked(err.get("Message") or "", account, *names)
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _paged(call, key: str, token_in: str, token_out: str, **kwargs) -> list:
    """Every ``key`` entry of a paginated IoT list, following ``token_out`` into ``token_in``."""
    out: list = []
    while True:
        page = call(**kwargs)
        out.extend(page.get(key, []))
        if not page.get(token_out):
            return out
        kwargs[token_in] = page[token_out]


def _attached_policies(iot, cert_arn: str) -> list:
    return _paged(iot.list_attached_policies, "policies", "marker", "nextMarker", target=cert_arn)


def _thing_principals(iot, thing_name: str) -> list:
    return _paged(iot.list_thing_principals_v2, "thingPrincipalObjects", "nextToken", "nextToken",
                  thingName=thing_name)


def _until_empty(read, what: str) -> None:
    """Detaches propagate asynchronously: poll ``read()`` until empty within the deadline."""
    deadline = time.monotonic() + _DETACH_DEADLINE_S
    while True:
        left = read()
        if not left:
            return
        assert time.monotonic() < deadline, (
            f"{what} still lists {left!r} {_DETACH_DEADLINE_S}s after the attachment was removed"
        )
        time.sleep(2)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation-wired policy and thing attachment of a CSR-issued certificate read back
    through IoT; dropping the attachments detaches both, and deleting the stack removes the rest.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-policyprincipalattachment.html
    """
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-iotattach-")
    policy_name = ctx.unique_name("sim2real-iot-policy-")
    thing_name = ctx.unique_name("sim2real-iot-thing-")
    csr, csr_public_key = _generate_csr(ctx.unique_name("sim2real-iot-device-"))

    stack_id = create_stack(ctx, cfn, stack,
                            _template(policy_name, thing_name, csr, attachments=True))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    cert_id = outputs["CertificateRef"]
    cert_arn = outputs["CertificateArn"]

    # AWS::IoT::Policy
    assert outputs["PolicyRef"] == policy_name, (
        f"Ref of the Policy resource is {outputs['PolicyRef']!r}, expected the policy name "
        f"{policy_name!r}"
    )
    policy = iot.get_policy(policyName=policy_name)
    assert policy["policyName"] == policy_name, (
        f"GetPolicy returned policyName {policy['policyName']!r}, expected {policy_name!r}"
    )
    assert json.loads(policy["policyDocument"]) == _POLICY_DOCUMENT, (
        f"expected the declared PolicyDocument, GetPolicy reports {policy['policyDocument']!r}"
    )
    assert outputs["PolicyArn"] == policy["policyArn"], (
        f"GetAtt Arn is {outputs['PolicyArn']!r}, GetPolicy reports {policy['policyArn']!r}"
    )

    # AWS::IoT::Thing
    assert outputs["ThingRef"] == thing_name, (
        f"Ref of the Thing resource is {outputs['ThingRef']!r}, expected {thing_name!r}"
    )
    thing = iot.describe_thing(thingName=thing_name)
    assert thing["thingName"] == thing_name, f"DescribeThing thingName {thing['thingName']!r}"
    assert outputs["ThingArn"] == thing["thingArn"], (
        f"GetAtt Arn is {outputs['ThingArn']!r}, DescribeThing reports {thing['thingArn']!r}"
    )

    # AWS::IoT::Certificate: Ref and Arn against IoT's listing; the cert carries the CSR's key.
    listed = [c for c in _paged(iot.list_certificates, "certificates", "marker", "nextMarker")
              if c["certificateArn"] == cert_arn]
    assert len(listed) == 1, f"expected one ListCertificates entry with the GetAtt Arn, got {len(listed)}"
    assert listed[0]["certificateId"] == cert_id, (
        f"ListCertificates certificateId {listed[0]['certificateId']!r} != Ref {cert_id!r}"
    )
    cert = iot.describe_certificate(certificateId=cert_id)["certificateDescription"]
    assert cert["certificateArn"] == cert_arn, (
        f"GetAtt Arn is {cert_arn!r}, DescribeCertificate reports {cert['certificateArn']!r}"
    )
    assert cert["status"] == "ACTIVE", (
        f"expected status 'ACTIVE' as declared, DescribeCertificate reports {cert['status']!r}"
    )
    assert _cert_public_key(cert["certificatePem"]) == csr_public_key, (
        "the issued certificate's public key is not the CertificateSigningRequest's"
    )

    # AWS::IoT::PolicyPrincipalAttachment and AWS::IoT::ThingPrincipalAttachment
    attached_names = sorted(p["policyName"] for p in _attached_policies(iot, cert_arn))
    assert attached_names == [policy_name], (
        f"expected ListAttachedPolicies(target=cert) to list only {policy_name!r}, got "
        f"{attached_names!r}"
    )
    principal_arns = sorted(p["principal"] for p in _thing_principals(iot, thing_name))
    assert principal_arns == [cert_arn], (
        f"expected ListThingPrincipalsV2({thing_name!r}) to list only the certificate, got "
        f"{principal_arns!r}"
    )

    # Each attachment's own delete: drop both while the certificate, policy and thing remain.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(policy_name, thing_name, csr, attachments=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"attachment-removing update ended {status!r}"
    _until_empty(lambda: _attached_policies(iot, cert_arn), "ListAttachedPolicies(target=cert)")
    _until_empty(lambda: _thing_principals(iot, thing_name), f"ListThingPrincipalsV2({thing_name!r})")
    still = (iot.get_policy(policyName=policy_name)["policyName"],
             iot.describe_thing(thingName=thing_name)["thingName"],
             iot.describe_certificate(certificateId=cert_id)["certificateDescription"]["status"])
    assert still == (policy_name, thing_name, "ACTIVE"), (
        f"removing the attachments changed the policy, thing or certificate: {still!r}"
    )

    delete_stack(cfn, stack_id)

    expect_error(lambda: iot.get_policy(policyName=policy_name), *_POLICY_GONE)
    cert_gone = ("ResourceNotFoundException", f"CertificateId {cert_id} does not exist")
    expect_error(lambda: iot.describe_certificate(certificateId=cert_id), *cert_gone)
    got = _refusal(lambda: iot.describe_thing(thingName=thing_name), ctx.account, thing_name)
    assert got == _THING_GONE, f"DescribeThing of the deleted thing answered {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
