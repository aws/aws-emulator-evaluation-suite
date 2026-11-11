"""deploy-iot-cacertificate-sni-only-round-trip-and-delete."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-iot-cacertificate-sni-only-round-trip-and-delete"
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

_CA_GONE = ("ResourceNotFoundException", "Requested CA Certificate does not exist.")
_CA_CONFIG = """[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = {cn}
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


def _generate_ca_pem(common_name: str) -> str:
    """A fresh self-signed CA certificate, so no run collides with another's registration."""
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        conf = os.path.join(d, "ca.cnf")
        with open(conf, "w") as f:
            f.write(_CA_CONFIG.format(cn=common_name))
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-config", conf, "-keyout", os.path.join(d, "ca.key"),
             "-out", os.path.join(d, "ca.pem")],
            check=True, capture_output=True, timeout=60,
        )
        with open(os.path.join(d, "ca.pem")) as f:
            return f.read()


def _template(ca_pem: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "CaCert": {
                "Type": "AWS::IoT::CACertificate",
                "Properties": {
                    "CACertificatePem": ca_pem,
                    "Status": "ACTIVE",
                    "CertificateMode": "SNI_ONLY",
                },
            },
        },
        "Outputs": {
            "CaCertRef": {"Value": {"Ref": "CaCert"}},
            "CaCertArn": {"Value": {"Fn::GetAtt": ["CaCert", "Arn"]}},
        },
    })


def _ca_certificates(iot) -> list[dict]:
    """Every ListCACertificates entry, following nextMarker."""
    out: list[dict] = []
    kwargs: dict = {}
    while True:
        page = iot.list_ca_certificates(**kwargs)
        out.extend(page.get("certificates", []))
        if not page.get("nextMarker"):
            return out
        kwargs["marker"] = page["nextMarker"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation SNI_ONLY AWS::IoT::CACertificate reads back through IoT with the declared
    PEM, status and mode, its Ref and Arn match IoT's listing, and deleting the stack removes it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-cacertificate.html
    """
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-iotcacert-")
    ca_pem = _generate_ca_pem(ctx.unique_name("sim2real-iot-ca-"))

    stack_id = create_stack(ctx, cfn, stack, _template(ca_pem))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    cert_id = outputs["CaCertRef"]
    cert_arn = outputs["CaCertArn"]

    # Ref and Arn against IoT's own listing, an independent read.
    listed = [c for c in _ca_certificates(iot) if c["certificateArn"] == cert_arn]
    assert len(listed) == 1, (
        f"expected exactly one ListCACertificates entry with the GetAtt Arn, got {len(listed)}"
    )
    assert listed[0]["certificateId"] == cert_id, (
        f"ListCACertificates certificateId {listed[0]['certificateId']!r} != Ref {cert_id!r}"
    )

    cert = iot.describe_ca_certificate(certificateId=cert_id)["certificateDescription"]
    assert cert["certificateArn"] == cert_arn, (
        f"GetAtt Arn is {cert_arn!r}, DescribeCaCertificate reports {cert['certificateArn']!r}"
    )
    assert cert["certificatePem"].strip() == ca_pem.strip(), (
        "DescribeCaCertificate certificatePem does not match the template's CACertificatePem"
    )
    assert cert["status"] == "ACTIVE", (
        f"expected status 'ACTIVE' as declared, DescribeCaCertificate reports {cert['status']!r}"
    )
    assert cert["certificateMode"] == "SNI_ONLY", (
        f"expected certificateMode 'SNI_ONLY' as declared, DescribeCaCertificate reports "
        f"{cert['certificateMode']!r}"
    )

    delete_stack(cfn, stack_id)
    expect_error(lambda: iot.describe_ca_certificate(certificateId=cert_id), *_CA_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
