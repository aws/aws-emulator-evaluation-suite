"""deploy-rolesanywhere-trust-anchor-crl-and-profile-round-trip-then-delete."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "deploy-rolesanywhere-trust-anchor-crl-and-profile-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "rolesanywhere"]

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

def _generate_ca_and_crl():
    """A fresh self-signed CA cert and a CRL it signs, revoking one made-up serial.

    Generated per run (no fixed key material): the CA key only ever signs this run's own CRL.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-rolesanywhere-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(x509.random_serial_number())
        .revocation_date(now)
        .build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=2))
        .add_revoked_certificate(revoked)
        .sign(key, hashes.SHA256())
    )
    ca_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode()
    return ca_pem, crl_pem


def _template(ta_name, crl_name, role_name, profile_name, ca_pem, crl_pem, children=True):
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TrustAnchor": {
                "Type": "AWS::RolesAnywhere::TrustAnchor",
                "Properties": {
                    "Name": ta_name,
                    "Enabled": True,
                    "Source": {
                        "SourceType": "CERTIFICATE_BUNDLE",
                        "SourceData": {"X509CertificateData": ca_pem},
                    },
                    "Tags": [{"Key": "sim2real-trustanchor", "Value": ta_name}],
                },
            },
            "Crl": {
                "Type": "AWS::RolesAnywhere::CRL",
                "Properties": {
                    "Name": crl_name,
                    "CrlData": crl_pem,
                    "Enabled": True,
                    "TrustAnchorArn": {"Fn::GetAtt": ["TrustAnchor", "TrustAnchorArn"]},
                    "Tags": [{"Key": "sim2real-crl", "Value": crl_name}],
                },
            },
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "rolesanywhere.amazonaws.com"},
                            "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                            "Condition": {"ArnEquals": {
                                "aws:SourceArn": {"Fn::GetAtt": ["TrustAnchor", "TrustAnchorArn"]}
                            }},
                        }],
                    },
                },
            },
            "Profile": {
                "Type": "AWS::RolesAnywhere::Profile",
                "Properties": {
                    "Name": profile_name,
                    "Enabled": True,
                    "RoleArns": [{"Fn::GetAtt": ["Role", "Arn"]}],
                    "DurationSeconds": 3600,
                    "Tags": [{"Key": "sim2real-profile", "Value": profile_name}],
                },
            },
        },
        "Outputs": {
            "TrustAnchorRef": {"Value": {"Ref": "TrustAnchor"}},
            "TrustAnchorArn": {"Value": {"Fn::GetAtt": ["TrustAnchor", "TrustAnchorArn"]}},
            "CrlRef": {"Value": {"Ref": "Crl"}},
            "ProfileRef": {"Value": {"Ref": "Profile"}},
            "ProfileArn": {"Value": {"Fn::GetAtt": ["Profile", "ProfileArn"]}},
        },
    }
    if not children:
        for key in ("Crl", "Role", "Profile"):
            del template["Resources"][key]
        template["Outputs"] = {k: v for k, v in template["Outputs"].items() if "Trust" in k}
    return json.dumps(template)


_TA_NOT_FOUND = ("ResourceNotFoundException", "TrustAnchor not found")


def _not_found(arn):
    """The NotFound RolesAnywhere answers for a deleted CRL or profile."""
    return ("ResourceNotFoundException", f"The item doesn't exist. arn: {arn} ; aborting.")


def _tags(ra, arn):
    """The resource's tags as {key: value}, without the ``aws:`` system tags."""
    rows = ra.list_tags_for_resource(resourceArn=arn).get("tags", [])
    return {t["key"]: t["value"] for t in rows if not t["key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation trust anchor, CRL and profile read back through RolesAnywhere, then gone.

    Ref, every templated property and tag match RolesAnywhere; dropping the CRL and profile in an
    update removes both while the trust anchor answers, and the stack delete removes it.
    """
    cf = ctx.client("cloudformation")
    ra = ctx.client("rolesanywhere")
    stack = ctx.unique_name("sim2real-ra-cfn-")
    ta_name = ctx.unique_name("sim2real-ra-ta-")
    crl_name = ctx.unique_name("sim2real-ra-crl-")
    role_name = ctx.unique_name("sim2real-ra-role-")
    profile_name = ctx.unique_name("sim2real-ra-profile-")
    ca_pem, crl_pem = _generate_ca_and_crl()
    names = (ta_name, crl_name, role_name, profile_name, ca_pem, crl_pem)

    stack_id = create_stack(ctx, cf, stack, _template(*names),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    arn_prefix = f"arn:{partition}:rolesanywhere:{ctx.region}:{ctx.account}"

    # Ref against an independent read (List* by the declared name), never a read by the Ref.
    listed_ta = [t["trustAnchorId"] for t in paginate(ra, "list_trust_anchors", "trustAnchors")
                 if t["name"] == ta_name]
    assert listed_ta == [out["TrustAnchorRef"]], (
        f"ListTrustAnchors found {listed_ta!r} for Ref {out['TrustAnchorRef']!r}"
    )
    listed_crl = [c["crlId"] for c in paginate(ra, "list_crls", "crls") if c["name"] == crl_name]
    assert listed_crl == [out["CrlRef"]], f"ListCrls found {listed_crl!r} for Ref {out['CrlRef']!r}"
    listed_profile = [p["profileId"] for p in paginate(ra, "list_profiles", "profiles")
                      if p["name"] == profile_name]
    assert listed_profile == [out["ProfileRef"]], (
        f"ListProfiles found {listed_profile!r} for Ref {out['ProfileRef']!r}"
    )

    # Deep reads: the read-only GetAtt, and every templated property, including the CRL's link.
    ta = ra.get_trust_anchor(trustAnchorId=out["TrustAnchorRef"])["trustAnchor"]
    ta_arn = f"{arn_prefix}:trust-anchor/{out['TrustAnchorRef']}"
    assert (ta["trustAnchorArn"], out["TrustAnchorArn"]) == (ta_arn, ta_arn), (
        f"GetTrustAnchor {ta['trustAnchorArn']!r}, GetAtt {out['TrustAnchorArn']!r}, "
        f"expected {ta_arn!r}"
    )
    got_ta = (ta["name"], ta["enabled"], ta["source"]["sourceType"],
              ta["source"]["sourceData"]["x509CertificateData"])
    assert got_ta == (ta_name, True, "CERTIFICATE_BUNDLE", ca_pem), f"trust anchor {got_ta!r}"
    ta_tags = _tags(ra, ta_arn)
    assert ta_tags == {"sim2real": stack, "sim2real-trustanchor": ta_name}, f"tags {ta_tags!r}"
    ta_created = ta["createdAt"]

    crl = ra.get_crl(crlId=out["CrlRef"])["crl"]
    got_crl = (crl["name"], crl["trustAnchorArn"], crl["enabled"], crl["crlData"].decode())
    assert got_crl == (crl_name, ta_arn, True, crl_pem), f"CRL reads {got_crl!r}"
    crl_tags = _tags(ra, crl["crlArn"])
    assert crl_tags == {"sim2real": stack, "sim2real-crl": crl_name}, f"CRL tags {crl_tags!r}"

    profile = ra.get_profile(profileId=out["ProfileRef"])["profile"]
    profile_arn = f"{arn_prefix}:profile/{out['ProfileRef']}"
    assert (profile["profileArn"], out["ProfileArn"]) == (profile_arn, profile_arn), (
        f"GetProfile {profile['profileArn']!r}, GetAtt {out['ProfileArn']!r}, "
        f"expected {profile_arn!r}"
    )
    got_profile = (profile["name"], profile["roleArns"], profile["durationSeconds"],
                   profile["enabled"])
    want_profile = (profile_name, [f"arn:{partition}:iam::{ctx.account}:role/{role_name}"], 3600,
                    True)
    assert got_profile == want_profile, f"profile reads {got_profile!r}, expected {want_profile!r}"
    profile_tags = _tags(ra, profile_arn)
    assert profile_tags == {"sim2real": stack, "sim2real-profile": profile_name}, (
        f"profile tags {profile_tags!r}"
    )

    # Children first: an update dropping the CRL and the profile removes both through
    # RolesAnywhere while the same trust anchor (createdAt) still answers.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(*names, children=False),
                    Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    expect_error(lambda: ra.get_crl(crlId=out["CrlRef"]),
                 *_not_found(f"{arn_prefix}:crl/{out['CrlRef']}"))
    expect_error(lambda: ra.get_profile(profileId=out["ProfileRef"]), *_not_found(profile_arn))
    still = ra.get_trust_anchor(trustAnchorId=out["TrustAnchorRef"])["trustAnchor"]
    assert still["createdAt"] == ta_created, f"trust anchor after the update reads {still!r}"

    delete_stack(cf, stack_id)
    expect_error(lambda: ra.get_trust_anchor(trustAnchorId=out["TrustAnchorRef"]), *_TA_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
