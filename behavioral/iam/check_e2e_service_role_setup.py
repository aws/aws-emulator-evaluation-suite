"""e2e-service-role-setup."""
from __future__ import annotations

import json
import time
from urllib.parse import unquote

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-service-role-setup"
GROUP = 'e2e_workflows'
SERVICES = ['iam']

#: IAM is eventually consistent: each read after a write converges within this bound and returns
#: as soon as the expected value or refusal holds.
_CONVERGE_S = 60

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Service role setup as IaC does it: the role reports its ARN, path and trust document, the
    policy attaches and detaches, and both resources are gone after delete."""
    iam = ctx.client("iam")
    partition = _partition(ctx)
    # Create a role with Lambda trust policy
    lambda_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_name = ctx.unique_name("sim2real-behav-role-")
    path = f"/sim2real/{ctx.unique_name('p-')}/"
    created_role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=lambda_trust,
        Path=path,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda n=role_name: _quiet(lambda: iam.delete_role(RoleName=n)))
    expected_role_arn = f"arn:{partition}:iam::{ctx.account}:role{path}{role_name}"
    assert created_role["Arn"] == expected_role_arn, f"CreateRole Arn {created_role['Arn']!r} != {expected_role_arn!r}"
    assert created_role["Path"] == path, f"CreateRole Path {created_role['Path']!r} != {path!r}"

    # Create a minimal policy allowing s3:GetObject on sim2real-behav-* resources
    s3_policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:{partition}:s3:::sim2real-behav-*/*",
                }
            ],
        }
    )
    policy_name = ctx.unique_name("sim2real-behav-pol-")
    policy_arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=s3_policy_doc,
        Path=path,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=policy_arn: _quiet(lambda: iam.delete_policy(PolicyArn=a)))
    expected_arn = f"arn:{partition}:iam::{ctx.account}:policy{path}{policy_name}"
    assert policy_arn == expected_arn, f"expected policy Arn {expected_arn!r}, got {policy_arn!r}"

    # Attach the policy to the role
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda r=role_name, p=policy_arn: _quiet(lambda: iam.detach_role_policy(RoleName=r, PolicyArn=p)))
    count = _converge(lambda: iam.get_policy(PolicyArn=policy_arn)["Policy"]["AttachmentCount"],
                      lambda c: c == 1)
    assert count == 1, f"expected GetPolicy AttachmentCount 1 after attach, got {count!r}"

    # GetRole reports the role's ARN, path and the trust document that was sent.
    role_data = iam.get_role(RoleName=role_name)["Role"]
    assert role_data["Arn"] == expected_role_arn, f"GetRole Arn {role_data['Arn']!r} != {expected_role_arn!r}"
    assert role_data["Path"] == path, f"GetRole Path {role_data['Path']!r} != {path!r}"
    trust = _policy_doc(role_data["AssumeRolePolicyDocument"])
    sent = _policy_doc(lambda_trust)
    assert trust == sent, f"GetRole trust document {trust!r} != the document sent {sent!r}"

    # List attached policies, verify the policy is there
    resp = iam.list_attached_role_policies(RoleName=role_name)
    attached_arns = [p["PolicyArn"] for p in resp["AttachedPolicies"]]
    assert policy_arn in attached_arns, (
        f"Policy {policy_arn} not found in attached policies: {attached_arns}"
    )

    # Detach the policy and verify it's gone
    iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    attached_arns2 = _converge(
        lambda: [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]],
        lambda arns: policy_arn not in arns,
    )
    assert policy_arn not in attached_arns2, f"Policy {policy_arn} still attached after detach"
    count = _converge(lambda: iam.get_policy(PolicyArn=policy_arn)["Policy"]["AttachmentCount"],
                      lambda c: c == 0)
    assert count == 0, f"expected GetPolicy AttachmentCount 0 after detach, got {count!r}"

    # Delete the policy, then prove it gone: by-ARN read, path listing, mutation on the dead ARN.
    iam.delete_policy(PolicyArn=policy_arn)
    policy_gone = ("NoSuchEntity", f"Policy {policy_arn} was not found.")
    got = _refusal(_eventual_error(lambda: iam.get_policy(PolicyArn=policy_arn)), 404)
    assert got == policy_gone, f"GetPolicy on the deleted policy: expected {policy_gone}, got {got!r}"
    listed = _converge(lambda: [
        p["Arn"]
        for page in iam.get_paginator("list_policies").paginate(Scope="Local", PathPrefix=path)
        for p in page["Policies"]
    ], lambda arns: policy_arn not in arns)
    assert policy_arn not in listed, f"deleted policy still listed under its path: {listed!r}"
    policy_unattachable = ("NoSuchEntity", f"Policy {policy_arn} does not exist or is not attachable.")
    got = _refusal(
        _eventual_error(lambda: iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument=s3_policy_doc)),
        404,
    )
    assert got == policy_unattachable, (
        f"CreatePolicyVersion on the deleted policy: expected {policy_unattachable}, got {got!r}"
    )

    # Delete the role, then prove it gone the same way.
    iam.delete_role(RoleName=role_name)
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    got = _refusal(_eventual_error(lambda: iam.get_role(RoleName=role_name)), 404)
    assert got == role_gone, f"GetRole on the deleted role: expected {role_gone}, got {got!r}"
    roles = _converge(
        lambda: [r["RoleName"] for page in iam.get_paginator("list_roles").paginate(PathPrefix=path) for r in page["Roles"]],
        lambda names: not names,
    )
    assert not roles, f"deleted role still listed under its path: {roles!r}"
    got = _refusal(_eventual_error(lambda: iam.update_role(RoleName=role_name, Description="x")), 404)
    assert got == role_gone, f"UpdateRole on the deleted role: expected {role_gone}, got {got!r}"


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _converge(probe, ok, timeout_s=_CONVERGE_S, interval_s=2.0):
    """Re-read until ok(value) holds or the bound passes; return the last value read."""
    deadline = time.monotonic() + timeout_s
    while True:
        value = probe()
        if ok(value) or time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)


def _eventual_error(fn, timeout_s=_CONVERGE_S, interval_s=2.0):
    """Like _error, but a call that still succeeds is retried until the bound passes (IAM's
    deletes propagate eventually); a success at the deadline raises AssertionError."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be rejected within {timeout_s}s, but it still succeeds: {result!r}")
        time.sleep(interval_s)


def _refusal(resp, status):
    """(code, message) of a refusal, after grading its HTTP status class (AWS answers `status`)."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"expected HTTP {status // 100}xx for {err.get('Code')!r}, got {got_status!r}"
    )
    return err.get("Code"), err.get("Message")


def _policy_doc(doc):
    """A policy document as a comparable value: parsed from JSON (URL-decoded when IAM returns it
    encoded), with each single-element list read as its one element, as IAM treats them alike."""
    if isinstance(doc, str):
        doc = json.loads(unquote(doc) if doc.lstrip().startswith("%") else doc)
    return _collapse(doc)


def _collapse(value):
    if isinstance(value, list):
        items = [_collapse(v) for v in value]
        return items[0] if len(items) == 1 else items
    if isinstance(value, dict):
        return {k: _collapse(v) for k, v in value.items()}
    return value


def _quiet(fn):
    """Teardown call that tolerates the resource already being gone (the body deletes it)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
