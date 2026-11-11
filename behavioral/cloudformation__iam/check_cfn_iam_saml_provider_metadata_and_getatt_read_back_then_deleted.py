"""cfn-iam-saml-provider-metadata-and-getatt-read-back-then-deleted."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "cfn-iam-saml-provider-metadata-and-getatt-read-back-then-deleted"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

def _self_signed_cert_der(common_name: str) -> bytes:
    """A throwaway self-signed certificate, DER-encoded, for a synthetic SAML IdP."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=10))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _saml_metadata_xml(entity_id: str, cert_b64: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">'
        '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<KeyDescriptor use="signing">'
        '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
        f'<X509Data><X509Certificate>{cert_b64}</X509Certificate></X509Data>'
        '</KeyInfo>'
        '</KeyDescriptor>'
        f'<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="https://{entity_id}/sso"/>'
        '</IDPSSODescriptor>'
        '</EntityDescriptor>'
    )


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::IAM::SAMLProvider is created in IAM and removed with its stack.

    Ref and the Arn GetAtt equal the documented ARN IAM lists, the metadata document reads back,
    and after the stack delete IAM answers NoSuchEntity for the ARN.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-samlprovider.html
    """
    try:
        from cryptography import x509  # noqa: F401
    except ImportError as exc:
        raise RequiredToolMissing(["cryptography"]) from exc
    import base64

    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    provider_name = ctx.unique_name("sim2real-saml-")
    entity_id = ctx.unique_name("sim2real-idp-") + ".example.com"

    cert_der = _self_signed_cert_der(entity_id)
    cert_b64 = base64.b64encode(cert_der).decode("ascii")
    metadata_xml = _saml_metadata_xml(entity_id, cert_b64)

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Provider": {
                "Type": "AWS::IAM::SAMLProvider",
                "Properties": {
                    "Name": provider_name,
                    "SamlMetadataDocument": metadata_xml,
                },
            },
        },
        "Outputs": {
            "ProviderArn": {"Value": {"Fn::GetAtt": ["Provider", "Arn"]}},
            "ProviderRef": {"Value": {"Ref": "Provider"}},
        },
    })
    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-saml-"), template)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    provider_arn = f"arn:{partition}:iam::{ctx.account}:saml-provider/{provider_name}"

    # Ref and GetAtt against the documented format and IAM's own (unpaged) provider list.
    assert (outputs["ProviderRef"], outputs["ProviderArn"]) == (provider_arn, provider_arn), (
        f"Ref/GetAtt {outputs!r}, expected {provider_arn!r}"
    )
    listed = [p["Arn"] for p in iam.list_saml_providers()["SAMLProviderList"]
              if p["Arn"] == provider_arn]
    assert listed == [provider_arn], f"IAM lists {listed!r} for {provider_arn!r}"

    provider = iam.get_saml_provider(SAMLProviderArn=provider_arn)
    assert provider["SAMLMetadataDocument"] == metadata_xml, (
        f"IAM returns metadata {provider['SAMLMetadataDocument']!r}"
    )

    delete_stack(cfn, stack_id)
    until_raises(lambda: iam.get_saml_provider(SAMLProviderArn=provider_arn))
    expect_error(lambda: iam.get_saml_provider(SAMLProviderArn=provider_arn),
                 *("NoSuchEntity", f"Manifest not found for arn {provider_arn}"))

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
