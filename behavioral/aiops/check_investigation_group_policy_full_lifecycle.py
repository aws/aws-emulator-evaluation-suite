"""investigation-group-policy-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "investigation-group-policy-full-lifecycle"
GROUP = "policy"
SERVICES = ["aiops"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """Resource policy lifecycle: absent by default, PutInvestigationGroupPolicy attaches it, a second Put replaces it, Delete removes it."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)
    _name, arn = _create_group(ctx, aiops, role_arn)

    # Fresh group has no policy.
    code, message = _error(lambda: aiops.get_investigation_group_policy(identifier=arn))
    assert code == "ResourceNotFoundException", f"expected a fresh group to have no policy, got {code!r}"
    expected = "InvestigationGroupPolicy does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    account = ctx.client("sts").get_caller_identity()["Account"]

    policy_v1 = json.dumps(
        {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Sid": "AllowAlarmsV1",
                    "Effect": "Allow",
                    "Principal": {"Service": "aiops.alarms.cloudwatch.amazonaws.com"},
                    "Action": ["aiops:CreateInvestigation"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account},
                        "ArnLike": {"aws:SourceArn": f"arn:aws:cloudwatch:{ctx.region}:{account}:alarm:*"},
                    },
                }
            ],
        }
    )
    aiops.put_investigation_group_policy(identifier=arn, policy=policy_v1)

    got1 = aiops.get_investigation_group_policy(identifier=arn)
    assert got1["investigationGroupArn"] == arn, (
        f"expected the policy's investigationGroupArn to be {arn!r}, got {got1['investigationGroupArn']!r}"
    )
    parsed1 = json.loads(got1["policy"])
    # Compare semantically rather than requiring byte-for-byte JSON equality: AWS may
    # normalize the stored policy document (e.g. re-serialize key order, canonicalize
    # single-item lists). The Sid and granted Action set are the load-bearing content.
    sid1 = parsed1["Statement"][0]["Sid"]
    assert sid1 == "AllowAlarmsV1", f"expected the stored policy's Sid to be 'AllowAlarmsV1', got {sid1!r}"
    actions1 = set(_as_list(parsed1["Statement"][0]["Action"]))
    assert actions1 == {"aiops:CreateInvestigation"}, f"expected {{'aiops:CreateInvestigation'}}, got {actions1!r}"

    # A second Put replaces (does not merge with) the first policy.
    policy_v2 = json.dumps(
        {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Sid": "AllowAlarmsV2",
                    "Effect": "Allow",
                    "Principal": {"Service": "aiops.alarms.cloudwatch.amazonaws.com"},
                    "Action": ["aiops:CreateInvestigation", "aiops:CreateInvestigationEvent"],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account},
                        "ArnLike": {"aws:SourceArn": f"arn:aws:cloudwatch:{ctx.region}:{account}:alarm:*"},
                    },
                }
            ],
        }
    )
    aiops.put_investigation_group_policy(identifier=arn, policy=policy_v2)

    got2 = aiops.get_investigation_group_policy(identifier=arn)
    parsed2 = json.loads(got2["policy"])
    sid2 = parsed2["Statement"][0]["Sid"]
    assert sid2 == "AllowAlarmsV2", f"expected the replaced policy's Sid to be 'AllowAlarmsV2', got {sid2!r}"
    actions2 = set(_as_list(parsed2["Statement"][0]["Action"]))
    expected2 = {"aiops:CreateInvestigation", "aiops:CreateInvestigationEvent"}
    assert actions2 == expected2, f"expected {expected2!r}, got {actions2!r}"
    assert parsed2 != parsed1, f"second Put should have replaced the first policy, but both read back as {parsed2!r}"

    aiops.delete_investigation_group_policy(identifier=arn)

    code_after_delete, message = _error(lambda: aiops.get_investigation_group_policy(identifier=arn))
    assert code_after_delete == "ResourceNotFoundException", (
        f"expected the deleted policy to read back not-found, got {code_after_delete!r}"
    )
    expected = "InvestigationGroupPolicy does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "aiops.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-aiops-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_group(ctx, aiops, role_arn: str, **kwargs):
    name = ctx.unique_name("sim2real-ig-")
    kwargs.setdefault("tags", {"sim2real": CHECK})
    deadline = time.monotonic() + 150.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = aiops.create_investigation_group(name=name, roleArn=role_arn, **kwargs)
            arn = resp["arn"]
            ctx.on_cleanup(lambda a=arn: aiops.delete_investigation_group(identifier=a))
            return name, arn
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if (
                code == "ResourceNotFoundException"
                or code == "ServiceQuotaExceededException"
                or (code == "ValidationException" and "assume" in msg.lower())
            ):
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

