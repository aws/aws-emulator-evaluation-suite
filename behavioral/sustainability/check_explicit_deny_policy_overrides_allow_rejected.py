"""explicit-deny-policy-overrides-allow-rejected."""
from __future__ import annotations

import datetime as dt
import json
import time

from behavioral_harness import tags

CHECK = "explicit-deny-policy-overrides-allow-rejected"
GROUP = "overly-permissive"
SERVICES = ["sustainability"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role whose policy allows sustainability:Get* and explicitly denies the same actions gets
    AccessDeniedException with its exact message (explicit deny wins), while the default caller succeeds."""
    sustainability = _sustainability_client(ctx)
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-sustain-explicitdeny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # A single identity policy that both allows the action broadly AND explicitly
    # denies it: under IAM's evaluation rules, an explicit Deny always wins over
    # any Allow, regardless of statement order within the document.
    policy_name = ctx.unique_name("sim2real-sustain-allow-then-deny-")
    conflicting_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sustainability:Get*", "Resource": "*"},
            {"Effect": "Deny", "Action": "sustainability:Get*", "Resource": "*"},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(conflicting_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    session_name = ctx.unique_name("sim2real-sess-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)

    start, end = _carbon_window(1)

    denied_client = ctx.client(
        "sustainability",
        region="us-east-1",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    def _bad():
        denied_client.get_estimated_carbon_emissions(TimePeriod={"Start": start, "End": end})

    code, message = _error(_bad)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} "
        "is not authorized to perform: sustainability:GetEstimatedCarbonEmissions on resource: "
        f"arn:aws:sustainability:{denied_client.meta.region_name}:{account_id}"
        ":/v1/estimated-carbon-emissions with an explicit deny in an identity-based policy"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the default caller's identical call succeeds.
    resp = sustainability.get_estimated_carbon_emissions(TimePeriod={"Start": start, "End": end})
    assert "Results" in resp and isinstance(resp["Results"], list), (
        f"expected the default-permission caller's identical call to succeed with a Results list, "
        f"got {resp!r}"
    )


def _sustainability_client(ctx):
    """AWS Sustainability accepts only requests signed for us-east-1, so the client is pinned to that region."""
    return ctx.client("sustainability", region="us-east-1")


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an accepted call fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _assume_role_with_retry(sts, role_arn, session_name, timeout_s=45.0, interval_s=3.0):
    # newly-created IAM roles/policies can take a few seconds to propagate before
    # they take effect; poll for that condition rather than sleeping a fixed duration.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_err}")


def _add_months(base: dt.datetime, months: int) -> dt.datetime:
    m = base.month - 1 + months
    y = base.year + m // 12
    m = m % 12 + 1
    return base.replace(year=y, month=m)


def _month_start(year: int, month: int) -> dt.datetime:
    return dt.datetime(year, month, 1, tzinfo=dt.timezone.utc)


def _carbon_window(months_back: int = 6) -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    end = _month_start(now.year, now.month)
    start = _add_months(end, -months_back)
    return start, end


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
