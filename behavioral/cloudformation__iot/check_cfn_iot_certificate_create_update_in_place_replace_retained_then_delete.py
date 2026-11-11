"""cfn-iot-certificate-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "cfn-iot-certificate-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A deleted certificate stops resolving within seconds; the bound only stops a hung poll.
_GONE_S = 60.0
#: DescribeCertificate's refusal of a certificate that no longer exists; {cert_id} is its id.
_CERT_GONE = ("ResourceNotFoundException", "CertificateId {cert_id} does not exist")
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::IoT::Certificate survives create, in-place update, retained replacement and delete.

    IoT issues a certificate bound to the CSR's key; a Status change keeps the certificate; a new
    CertificateSigningRequest under UpdateReplacePolicy Retain keeps the old certificate too.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-certificate.html
    """
    cfn = ctx.client("cloudformation")
    iot = ctx.client("iot")

    stack_name = ctx.unique_name("sim2real-cfnreal-iot-cert-")
    # Each key lives only in this process's memory; IoT receives the CSR alone.
    csr_a, key_a = _csr(ctx.unique_name("sim2real-cfnreal-device-a-"))
    csr_b, key_b = _csr(ctx.unique_name("sim2real-cfnreal-device-b-"))

    # Certificate ids exist only once IoT issues them; the retained one outlives the stack.
    issued: list[str] = []
    ctx.on_cleanup(lambda: _delete_certificates(iot, issued))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, IoT view, behaviour --------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(csr_a, "ACTIVE"), Tags=_TAGS
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    cert_a = _certificate_id(cfn, stack_id)
    issued.append(cert_a)
    cert = _certificate(iot, cert_a)
    outputs = _outputs(cfn, stack_id)
    assert outputs == {"Arn": cert["certificateArn"], "Id": cert_a}, (
        f"GetAtt Arn and Id must be DescribeCertificate's arn and the Ref id: {outputs!r}"
    )
    _assert_certificate(cert, cert_a, "ACTIVE", key_a)
    pem_a = cert["certificatePem"]

    # ---- 2. in-place update of the mutable Status -------------------------------------------
    rows = _update(ctx, cfn, stack_id, "Certificate", _template(csr_a, "INACTIVE"))
    _assert_updated_in_place(rows, cert_a)
    _assert_tracks(cfn, stack_id, "Certificate", cert_a)
    cert = _certificate(iot, cert_a)
    _assert_certificate(cert, cert_a, "INACTIVE", key_a)
    assert cert["certificatePem"] == pem_a, "an in-place Status update keeps the issued certificate"

    # ---- 3. a new CSR forces replacement; UpdateReplacePolicy Retain keeps the old one ------
    rows = _update(ctx, cfn, stack_id, "Certificate", _template(csr_b, "INACTIVE"))
    cert_b = _certificate_id(cfn, stack_id)
    issued.append(cert_b)
    assert cert_b != cert_a, f"a new CSR must issue a new certificate, still {cert_a!r}"
    _assert_replaced_and_retained(rows, cert_a, cert_b)
    _assert_certificate(_certificate(iot, cert_b), cert_b, "INACTIVE", key_b)
    old = _certificate(iot, cert_a)
    _assert_certificate(old, cert_a, "INACTIVE", key_a)
    assert old["certificatePem"] == pem_a, "the retained certificate must be the one first issued"

    # ---- 4. DeleteStack: the certificate it owns is gone, the retained one stays ------------
    _delete_and_confirm(ctx, cfn, stack_id)
    gone = (_CERT_GONE[0], _CERT_GONE[1].format(cert_id=cert_b))
    got = _poll(
        ctx,
        lambda: _refusal(lambda: iot.describe_certificate(certificateId=cert_b)),
        lambda e: e[0] != "<exists>",
        cap_s=_GONE_S,
        what=f"DescribeCertificate of {cert_b!r} refused after DeleteStack",
    )
    assert got == gone, f"DescribeCertificate after DeleteStack: {got!r}, not {gone!r}"
    _assert_certificate(_certificate(iot, cert_a), cert_a, "INACTIVE", key_a)


def _template(csr_pem: str, status: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Certificate": {
                    "Type": "AWS::IoT::Certificate",
                    # CertificateSigningRequest is create-only, so a new CSR replaces it.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "CertificateSigningRequest": csr_pem,
                        "Status": status,
                    },
                },
            },
            "Outputs": {
                "Arn": {"Value": {"Fn::GetAtt": ["Certificate", "Arn"]}},
                "Id": {"Value": {"Fn::GetAtt": ["Certificate", "Id"]}},
            },
        }
    )


def _csr(common_name: str) -> tuple[str, bytes]:
    """A fresh P-256 key's CSR (PEM) and the key's SubjectPublicKeyInfo (DER)."""
    key = ec.generate_private_key(ec.SECP256R1())
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return request.public_bytes(serialization.Encoding.PEM).decode(), _spki(key.public_key())


def _spki(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _outputs(cfn, stack_id: str) -> dict:
    stack = _stack(cfn, stack_id)
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _certificate_id(cfn, stack_id: str) -> str:
    """CloudFormation's view: the stack tracks the certificate by its 64-hex-digit id."""
    cert_id = _physical(cfn, stack_id, "Certificate")
    assert re.fullmatch(r"[0-9a-f]{64}", cert_id), (
        f"the PhysicalResourceId must be an IoT certificate id, got {cert_id!r}"
    )
    return cert_id


def _certificate(iot, cert_id: str) -> dict:
    return iot.describe_certificate(certificateId=cert_id)["certificateDescription"]


def _assert_certificate(cert: dict, cert_id: str, status: str, spki: bytes) -> None:
    """IoT's view and behaviour: the certificate's id, status and mode, and the key it binds."""
    got = (cert["certificateId"], cert["status"], cert["certificateMode"])
    assert got == (cert_id, status, "DEFAULT"), (
        f"DescribeCertificate must report {(cert_id, status, 'DEFAULT')!r}, got {got!r}"
    )
    issued = x509.load_pem_x509_certificate(cert["certificatePem"].encode())
    assert _spki(issued.public_key()) == spki, (
        f"certificate {cert_id!r} must carry the public key of the CSR it was issued for"
    )


def _refusal(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises, or an <exists> pair while it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    return "<exists>", "the call still succeeds"


def _delete_certificates(iot, cert_ids: list[str]) -> None:
    """Teardown: deactivate and delete each certificate; one DescribeCertificate refuses is gone."""
    for cert_id in cert_ids:
        try:
            iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
            iot.delete_certificate(certificateId=cert_id)
        except ClientError:
            gone = (_CERT_GONE[0], _CERT_GONE[1].format(cert_id=cert_id))
            if _refusal(lambda c=cert_id: iot.describe_certificate(certificateId=c)) != gone:
                raise


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
