"""list-domain-names-access-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-domain-names-access-denied"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDomainNames called by a principal with NO attached IAM policy (implicit default-deny)
    is rejected with AccessDeniedException rather than returning an empty or partial list --
    proving authorization is enforced BEFORE the list is assembled, not faked away."""
    denied_appsync, caller_arn, account_id = _create_denied_client(ctx, "appsync")

    code, message = _error(lambda: denied_appsync.list_domain_names())
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected = (
        f"User: {caller_arn} is not authorized to perform: appsync:ListDomainNames on resource: "
        f"arn:aws:appsync:{ctx.region}:{account_id}:* because no identity-based policy allows "
        "the appsync:ListDomainNames action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control, same file: the SAME call with the runner's normal (permissioned) credentials
    # reaches the service and returns a well-formed response, rather than also being denied --
    # proving the rejection above discriminates by principal, not by a target that unconditionally
    # rejects the operation. (There is no way to create a real, listable domain name in this account
    # to assert list membership: CreateDomainName rejects both a fabricated certificateArn and a
    # self-signed/imported one, and this account has no owned domain to DNS-validate a real ACM
    # certificate against.)
    appsync = ctx.client("appsync")
    resp = appsync.list_domain_names()
    assert isinstance(resp.get("domainNameConfigs"), list), (
        f"expected a domainNameConfigs list in the authorized response, got {resp!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _try_assume_role(sts, role_arn):
    from botocore.exceptions import ClientError

    try:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-denied")
        return resp
    except ClientError:
        return None


def _create_denied_client(ctx, service):
    """A `service` client signed as a freshly-created IAM role with NO attached policies, plus that
    session's ARN and the account id. IAM's implicit default-deny rejects every action on it unless
    the target fakes per-principal authorization away."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-deny-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    assumed = _poll_until(
        lambda: _try_assume_role(sts, role_arn),
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description=f"assume newly-created role {role_name}",
    )
    creds = assumed["Credentials"]
    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, assumed["AssumedRoleUser"]["Arn"], account_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
