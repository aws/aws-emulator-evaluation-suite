"""deploy-cfn-acmpca-permission-provisions-and-revokes."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-acmpca-permission-provisions-and-revokes"
GROUP = "deploy"
SERVICES = ["acm-pca", "cloudformation"]

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


# ---- Check-specific: the template, then run(). ----

_PRINCIPAL = "acm.amazonaws.com"
_ACTIONS = ["IssueCertificate", "GetCertificate", "ListPermissions"]


def _template(common_name: str, *, with_permission: bool) -> str:
    resources = {"Ca": {
        "Type": "AWS::ACMPCA::CertificateAuthority",
        "Properties": {
            "Type": "ROOT",
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
            "UsageMode": "SHORT_LIVED_CERTIFICATE",
        },
    }}
    outputs = {
        "CaRef": {"Value": {"Ref": "Ca"}},
        "CaArn": {"Value": {"Fn::GetAtt": ["Ca", "Arn"]}},
        "CaCsr": {"Value": {"Fn::GetAtt": ["Ca", "CertificateSigningRequest"]}},
    }
    if with_permission:
        resources["CaPermission"] = {
            "Type": "AWS::ACMPCA::Permission",
            "Properties": {
                "CertificateAuthorityArn": {"Ref": "Ca"},
                "Principal": _PRINCIPAL,
                "Actions": _ACTIONS,
            },
        }
        outputs["PermissionRef"] = {"Value": {"Ref": "CaPermission"}}
    return json.dumps({"Resources": resources, "Outputs": outputs})


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation CA and ACMPCA::Permission read back through ACM-PCA, then revoke.

    The CA's configuration, Ref, Arn and CSR and the permission's principal and actions match; an
    update dropping the permission revokes it from the live CA, and the stack delete leaves it DELETED.
    """
    cfn = ctx.client("cloudformation")
    pca = ctx.client("acm-pca")
    common_name = ctx.unique_name("sim2real-acmpca-perm-ca-")[:64]

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-acmpca-perm-"),
                            _template(common_name, with_permission=True))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    ca_arn = out["CaRef"]

    # Ref against an independent listing; read-only GetAtts against ACM-PCA.
    listed = [c["Arn"] for c in paginate(pca, "list_certificate_authorities",
                                         "CertificateAuthorities") if c["Arn"] == ca_arn]
    assert listed == [ca_arn], f"ListCertificateAuthorities found {listed!r} for Ref {ca_arn!r}"
    assert out["CaArn"] == ca_arn, f"GetAtt Arn {out['CaArn']!r} != Ref {ca_arn!r}"
    csr = pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    assert out["CaCsr"].strip() == csr.strip(), "GetAtt CertificateSigningRequest != the CA's CSR"

    ca = pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]
    cfg = ca["CertificateAuthorityConfiguration"]
    got = (ca["Type"], ca["UsageMode"], cfg["KeyAlgorithm"], cfg["SigningAlgorithm"],
           cfg["Subject"])
    want = ("ROOT", "SHORT_LIVED_CERTIFICATE", "RSA_2048", "SHA256WITHRSA",
            {"CommonName": common_name})
    assert got == want, f"CA reads {got!r}, expected {want!r}"

    # AWS::ACMPCA::Permission's Ref is its composite primary identifier.
    assert out["PermissionRef"] == f"{ca_arn}|{_PRINCIPAL}", (
        f"Permission Ref {out['PermissionRef']!r}"
    )
    perms = paginate(pca, "list_permissions", "Permissions", CertificateAuthorityArn=ca_arn)
    got = [(p["CertificateAuthorityArn"], p["Principal"], sorted(p["Actions"])) for p in perms]
    assert got == [(ca_arn, _PRINCIPAL, sorted(_ACTIONS))], f"permissions {got!r}"

    # Child before parent: the update drops only the permission; the same CA lists none.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(common_name, with_permission=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"permission-removing update ended {status!r}"
    remaining = paginate(pca, "list_permissions", "Permissions", CertificateAuthorityArn=ca_arn)
    assert remaining == [], f"permissions on {ca_arn!r} after the update: {remaining!r}"
    live = pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]
    assert live["CreatedAt"] == ca["CreatedAt"], "the update replaced the CA"

    delete_stack(cfn, stack_id)
    gone = pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]
    assert gone["Status"] == "DELETED", f"CA status after stack delete {gone['Status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
