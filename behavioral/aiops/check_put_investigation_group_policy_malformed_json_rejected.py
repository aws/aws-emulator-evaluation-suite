"""put-investigation-group-policy-malformed-json-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-investigation-group-policy-malformed-json-rejected"
GROUP = "overly-permissive"
SERVICES = ["aiops"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:aiops-investigation-group")
def run(ctx) -> None:
    """PutInvestigationGroupPolicy with a body that is not valid JSON/IAM policy is rejected with ValidationException, leaving the group without any attached policy."""
    aiops = ctx.client("aiops")
    role_arn = _create_role(ctx)
    _name, arn = _create_group(ctx, aiops, role_arn)

    malformed_policy = "{not-valid-json:::"
    code, message = _error(lambda: aiops.put_investigation_group_policy(identifier=arn, policy=malformed_policy))
    assert code == "ValidationException", (
        f"PutInvestigationGroupPolicy with a malformed (non-JSON) policy document was refused "
        f"with {code!r}, not ValidationException"
    )
    expected = "The specified resource policy document is invalid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no policy was attached by the rejected call.
    not_found_code, message = _error(lambda: aiops.get_investigation_group_policy(identifier=arn))
    assert not_found_code == "ResourceNotFoundException", (
        f"GetInvestigationGroupPolicy returned {not_found_code!r} after the malformed Put was "
        f"rejected — the rejected policy body left a policy attached"
    )
    expected = "InvestigationGroupPolicy does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a well-formed policy on the same group succeeds and round-trips.
    account = ctx.client("sts").get_caller_identity()["Account"]
    good_policy = json.dumps(
        {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Sid": "AllowAlarms",
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
    aiops.put_investigation_group_policy(identifier=arn, policy=good_policy)
    got = aiops.get_investigation_group_policy(identifier=arn)
    assert json.loads(got["policy"]) == json.loads(good_policy), (
        f"the round-tripped policy {got['policy']!r} does not match the well-formed policy that "
        f"was put {good_policy!r} — the well-formed control did not attach cleanly on a group "
        f"that had just rejected a malformed one"
    )


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


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-aiops-role-")
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_group(ctx, aiops, role_arn: str, **kwargs):
    name = ctx.unique_name("sim2real-ig-")
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
