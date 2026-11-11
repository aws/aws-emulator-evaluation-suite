"""service-role-at-root-path-reads-back-multi-statement-trust-and-two-attachments."""

from __future__ import annotations

import json
import time
from urllib.parse import unquote

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-role-at-root-path-reads-back-multi-statement-trust-and-two-attachments"
GROUP = "e2e_workflows"
SERVICES = ["iam"]

#: IAM is eventually consistent: each read after a write converges within this bound and returns
#: as soon as the expected value or refusal holds.
_CONVERGE_S = 40
_MAX_SESSION_S = 7200
_DESCRIPTION = "Service role für Aufgaben (ECS + Events)"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A role at the root path reads back its ARN without a path segment, its raised
    MaxSessionDuration, Latin-1 description and two-statement trust document; two policies under
    different paths attach and detach one at a time, and everything is gone after delete."""
    iam = ctx.client("iam")
    partition = _partition(ctx)
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TasksAndFunctions",
                "Effect": "Allow",
                "Principal": {"Service": ["ecs-tasks.amazonaws.com", "lambda.amazonaws.com"]},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
            },
            {
                "Sid": "Rules",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            },
        ],
    }
    role_name = ctx.unique_name("sim2real-behav-root-role-")
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Description=_DESCRIPTION,
        MaxSessionDuration=_MAX_SESSION_S,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda n=role_name: _quiet(lambda: iam.delete_role(RoleName=n)))
    expected_role_arn = f"arn:{partition}:iam::{ctx.account}:role/{role_name}"
    assert created["Arn"] == expected_role_arn, (
        f"CreateRole Arn {created['Arn']!r} != {expected_role_arn!r}"
    )
    assert created["Path"] == "/", f"CreateRole Path {created['Path']!r}, expected the default '/'"

    # Two customer managed policies: one under its own nested path, one at the root path.
    policy_path = f"/svc/{ctx.unique_name('pp-')}/"
    docs = {
        "nested": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Read",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [
                        f"arn:{partition}:s3:::sim2real-behav-*",
                        f"arn:{partition}:s3:::sim2real-behav-*/*",
                    ],
                },
            ],
        },
        "root": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Logs",
                    "Effect": "Allow",
                    "Action": "logs:PutLogEvents",
                    "Resource": f"arn:{partition}:logs:*:{ctx.account}:log-group:/sim2real/*",
                },
            ],
        },
    }
    arns = {}
    for label, path in (("nested", policy_path), ("root", "/")):
        name = ctx.unique_name(f"sim2real-behav-{label}-pol-")
        arn = iam.create_policy(
            PolicyName=name,
            PolicyDocument=json.dumps(docs[label]),
            Path=path,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Policy"]["Arn"]
        ctx.on_cleanup(lambda a=arn: _quiet(lambda: iam.delete_policy(PolicyArn=a)))
        expected = f"arn:{partition}:iam::{ctx.account}:policy{path}{name}"
        assert arn == expected, f"CreatePolicy ({label}) Arn {arn!r} != {expected!r}"
        arns[label] = (name, arn)

    for _name, arn in arns.values():
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(
            lambda r=role_name, p=arn: _quiet(
                lambda: iam.detach_role_policy(RoleName=r, PolicyArn=p)
            )
        )
    both = sorted(arns.values())
    attached = _converge(lambda: _attached(iam, role_name), lambda got: got == both)
    assert attached == both, f"ListAttachedRolePolicies {attached!r}, expected exactly {both!r}"
    for label, (_, arn) in arns.items():
        count = _converge(
            lambda a=arn: iam.get_policy(PolicyArn=a)["Policy"]["AttachmentCount"], lambda c: c == 1
        )
        assert count == 1, f"GetPolicy ({label}) AttachmentCount {count!r} after attach, expected 1"

    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["Arn"] == expected_role_arn, f"GetRole Arn {role['Arn']!r} != {expected_role_arn!r}"
    assert role["Path"] == "/", f"GetRole Path {role['Path']!r}, expected '/'"
    assert role["MaxSessionDuration"] == _MAX_SESSION_S, (
        f"GetRole MaxSessionDuration {role['MaxSessionDuration']!r}, expected {_MAX_SESSION_S}"
    )
    assert role["Description"] == _DESCRIPTION, (
        f"GetRole Description {role['Description']!r} != {_DESCRIPTION!r}"
    )
    trust = _policy_doc(role["AssumeRolePolicyDocument"])
    sent = _policy_doc(trust_doc)
    assert trust == sent, f"GetRole trust document {trust!r} != the document sent {sent!r}"

    # Detach the nested-path policy only: exactly the root-path policy stays attached.
    iam.detach_role_policy(RoleName=role_name, PolicyArn=arns["nested"][1])
    remaining = _converge(lambda: _attached(iam, role_name), lambda got: got == [arns["root"]])
    assert remaining == [arns["root"]], (
        f"after one detach ListAttachedRolePolicies {remaining!r}, expected {[arns['root']]!r}"
    )
    counts = {
        label: iam.get_policy(PolicyArn=arn)["Policy"]["AttachmentCount"]
        for label, (_, arn) in arns.items()
    }
    assert counts == {"nested": 0, "root": 1}, (
        f"AttachmentCount after one detach {counts!r}, expected nested 0 / root 1"
    )
    iam.detach_role_policy(RoleName=role_name, PolicyArn=arns["root"][1])
    remaining = _converge(lambda: _attached(iam, role_name), lambda got: got == [])
    assert remaining == [], (
        f"after both detaches ListAttachedRolePolicies {remaining!r}, expected none"
    )

    for label, (_, arn) in arns.items():
        iam.delete_policy(PolicyArn=arn)
        gone = ("NoSuchEntity", f"Policy {arn} was not found.")
        got = _refusal(_eventual_error(lambda a=arn: iam.get_policy(PolicyArn=a)), 404)
        assert got == gone, f"GetPolicy on the deleted {label} policy: expected {gone}, got {got!r}"

    iam.delete_role(RoleName=role_name)
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    got = _refusal(_eventual_error(lambda: iam.get_role(RoleName=role_name)), 404)
    assert got == role_gone, f"GetRole on the deleted role: expected {role_gone}, got {got!r}"
    got = _refusal(
        _eventual_error(lambda: iam.update_role(RoleName=role_name, MaxSessionDuration=3600)), 404
    )
    assert got == role_gone, f"UpdateRole on the deleted role: expected {role_gone}, got {got!r}"


def _attached(iam, role_name):
    """The role's attached managed policies as a sorted list of (PolicyName, PolicyArn)."""
    return sorted(
        (p["PolicyName"], p["PolicyArn"])
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name)
        for p in page["AttachedPolicies"]
    )


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
    """The error response of fn(); a call that still succeeds is retried until the bound passes
    (IAM's deletes propagate eventually), and a success at the deadline raises AssertionError."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected the call to be rejected within {timeout_s}s, but it still succeeds: {result!r}"
            )
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
    encoded), each single-element list read as its one element and each list of strings as a sorted
    list: IAM treats both alike and may reorder a principal list."""
    if isinstance(doc, str):
        doc = json.loads(unquote(doc) if doc.lstrip().startswith("%") else doc)
    return _collapse(doc)


def _collapse(value):
    if isinstance(value, list):
        items = [_collapse(v) for v in value]
        if len(items) == 1:
            return items[0]
        return sorted(items) if all(isinstance(i, str) for i in items) else items
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
