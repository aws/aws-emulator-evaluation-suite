"""deploy-cfn-acmpca-permission-invalid-principal-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-acmpca-permission-invalid-principal-rejected"
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

_VALID_PRINCIPAL = "acm.amazonaws.com"
_INVALID_PRINCIPAL = "not-acm.amazonaws.com"
_ACTIONS = ["IssueCertificate", "GetCertificate", "ListPermissions"]
_REJECTED = (
    "The principal specified is not supported. (Service: AWSACMPCA; Status Code: 400; "
    "Error Code: ValidationException; Request ID: <id>; Proxy: null)",
    "GeneralServiceException",
)


def _template(common_name: str, principal: str) -> str:
    return json.dumps({
        "Resources": {
            "Ca": {
                "Type": "AWS::ACMPCA::CertificateAuthority",
                "Properties": {
                    "Type": "ROOT",
                    "KeyAlgorithm": "RSA_2048",
                    "SigningAlgorithm": "SHA256WITHRSA",
                    "Subject": {"CommonName": common_name},
                    "UsageMode": "SHORT_LIVED_CERTIFICATE",
                },
            },
            "CaPermission": {
                "Type": "AWS::ACMPCA::Permission",
                "Properties": {
                    "CertificateAuthorityArn": {"Ref": "Ca"},
                    "Principal": principal,
                    "Actions": _ACTIONS,
                },
            },
        },
        "Outputs": {"CaArn": {"Value": {"Ref": "Ca"}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ACMPCA::Permission naming an unsupported principal fails to create.

    ACM-PCA refuses it and grants nothing on the CA, while the same template with a supported
    principal grants exactly the templated principal and actions.
    """
    cfn = ctx.client("cloudformation")
    pca = ctx.client("acm-pca")
    good_cn = ctx.unique_name("sim2real-acmpca-permok-ca-")[:64]
    bad_cn = ctx.unique_name("sim2real-acmpca-permbad-ca-")[:64]

    # Positive control: the same template, the Principal given a supported value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-acmpca-permok-"),
                           _template(good_cn, _VALID_PRINCIPAL))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_ca = stack_outputs(cfn, good_id)["CaArn"]
    good_perms = paginate(pca, "list_permissions", "Permissions", CertificateAuthorityArn=good_ca)
    got = [(p["Principal"], sorted(p["Actions"])) for p in good_perms]
    assert got == [(_VALID_PRINCIPAL, sorted(_ACTIONS))], f"control CA permissions {got!r}"

    # Rollback disabled: the CA stays, so the absence read targets a CA the check owns.
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-acmpca-permbad-"),
                          _template(bad_cn, _INVALID_PRINCIPAL), DisableRollback=True)
    status = wait_stack(cfn, bad_id)
    assert status == "CREATE_FAILED", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "CaPermission"), ctx.account)
    assert got == _REJECTED, f"CaPermission reason {got!r}, expected {_REJECTED!r}"

    bad_ca = cfn.describe_stack_resource(StackName=bad_id, LogicalResourceId="Ca")[
        "StackResourceDetail"]["PhysicalResourceId"]
    bad_perms = paginate(pca, "list_permissions", "Permissions", CertificateAuthorityArn=bad_ca)
    assert bad_perms == [], f"a permission was granted on {bad_ca!r}: {bad_perms!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
