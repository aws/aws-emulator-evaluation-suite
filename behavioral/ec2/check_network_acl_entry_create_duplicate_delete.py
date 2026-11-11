"""network-acl-entry-create-duplicate-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _probe_errors(client, probes):
    """Assert a batch of operations all fail with an expected error code.

    *probes* is a list of ``(client_method, kwargs, acceptable_codes, message)``; the error message must equal *message* exactly.
    Every mismatch is collected rather than raising on the first, and operations the installed botocore does not know about are
    reported as skipped. A ``ParamValidationError`` (the request never left the SDK) is not caught here: every probe in this file is
    well-formed, so one firing is a real bug in the check and must surface as an uncaught error. Returns ``(problems, skipped)``.
    """
    problems = []
    skipped = []
    for method, kwargs, expected, expected_message in probes:
        fn = getattr(client, method, None)
        if fn is None:
            skipped.append(method)
            continue
        try:
            fn(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            if code not in expected:
                problems.append(f"{method}: expected {sorted(expected)}, got {code}")
            elif message != expected_message:
                problems.append(f"{method}: expected message {expected_message!r}, got {message!r}")
        else:
            problems.append(f"{method}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems, skipped

CHECK = "network-acl-entry-create-duplicate-delete"
GROUP = 'vpc-networking'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkAcl + entry add/duplicate/delete semantics."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.101.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        time.sleep(2)

    resp = ec2.create_network_acl(VpcId=vpc_id, TagSpecifications=[{"ResourceType": "network-acl", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    acl_id = resp["NetworkAcl"]["NetworkAclId"]
    ctx.on_cleanup(lambda: ec2.delete_network_acl(NetworkAclId=acl_id))
    assert resp["NetworkAcl"]["IsDefault"] is False, "a created ACL must not be the default"

    entry = dict(
        NetworkAclId=acl_id,
        RuleNumber=100,
        Protocol="6",
        RuleAction="allow",
        Egress=False,
        CidrBlock="10.0.0.0/8",
        PortRange={"From": 80, "To": 80},
    )
    ec2.create_network_acl_entry(**entry)

    entries = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
    assert any(e["RuleNumber"] == 100 and not e["Egress"] for e in entries), (
        f"created entry not visible: {entries}"
    )

    # Reusing rule number 100 in the same direction with DIFFERENT contents must
    # conflict (an identical re-create is accepted idempotently by real EC2, so
    # that would not exercise the conflict path).
    conflicting = dict(entry, CidrBlock="192.0.2.0/24")
    problems, _ = _probe_errors(ec2, [
        (
            "create_network_acl_entry",
            conflicting,
            ("NetworkAclEntryAlreadyExists",),
            "The network acl entry identified by 100 already exists.",
        ),
    ])

    # The identical re-create the comment above promises is accepted idempotently:
    # prove it rather than just asserting the conflict and trusting the claim.
    ec2.create_network_acl_entry(**entry)
    entries_dup = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
    rule_100_ingress = [e for e in entries_dup if e["RuleNumber"] == 100 and not e["Egress"]]
    assert len(rule_100_ingress) == 1, (
        f"identical re-create of rule 100 must be idempotent, not duplicate: {rule_100_ingress}"
    )
    assert rule_100_ingress[0]["CidrBlock"] == "10.0.0.0/8", (
        "the rejected conflicting create must not have mutated the existing rule: "
        f"{rule_100_ingress[0]}"
    )

    ec2.delete_network_acl_entry(NetworkAclId=acl_id, RuleNumber=100, Egress=False)
    # DescribeNetworkAcls is eventually consistent — an immediate read after the delete can still
    # echo the entry under load. Poll until it's gone (bounded) before asserting absence.
    deadline = time.monotonic() + 30
    while True:
        entries2 = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
        if not any(e["RuleNumber"] == 100 and not e["Egress"] for e in entries2) or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert not any(e["RuleNumber"] == 100 and not e["Egress"] for e in entries2), (
        f"entry still present after delete: {entries2}"
    )

    # Deleting an entry that no longer exists must fail.
    more, _ = _probe_errors(ec2, [
        (
            "delete_network_acl_entry",
            {"NetworkAclId": acl_id, "RuleNumber": 100, "Egress": False},
            ("InvalidNetworkAclEntry.NotFound",),
            f"no ingress entry with number 100 in network ACL {acl_id}",
        ),
    ])
    problems += more
    assert not problems, "unexpected network ACL entry semantics:\n" + "\n".join(problems)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
