"""compose-environments-insufficient-privileges-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compose-environments-insufficient-privileges-blocked"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ComposeEnvironments on an application the caller is resource-level denied fails AccessDenied
    and creates no environment; a full-privilege caller passes authorization and fails only on
    the bogus version label."""
    eb = ctx.client("elasticbeanstalk")

    app = _create_app(ctx, eb)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    app_arn = f"arn:aws:elasticbeanstalk:{ctx.region}:{account_id}:application/{app}"

    restricted, _restricted_arn = _create_restricted_caller(
        ctx,
        allow_actions=["elasticbeanstalk:*"],
        deny_statements=[{"Effect": "Deny", "Action": "elasticbeanstalk:*", "Resource": app_arn}],
        name_hint="compose",
    )

    bogus_version = ctx.unique_name("sim2real-eb-bogus-version-")

    def _compose_restricted():
        restricted.compose_environments(ApplicationName=app, VersionLabels=[bogus_version])

    code, message = _poll_past_credential_propagation(_compose_restricted)
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    restricted_role_name = _restricted_arn.split("/")[-1]
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{restricted_role_name}/sim2real-eb is not "
        f"authorized to perform: elasticbeanstalk:ComposeEnvironments on resource: {app_arn}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    remaining = eb.describe_environments(ApplicationName=app, IncludeDeleted=False)["Environments"]
    assert remaining == [], f"expected no environments after the denied call, got {remaining!r}"

    # Positive control: a full-privilege caller passes the authorization check for the same
    # request and instead fails for an unrelated reason (the version label does not exist).
    admin_code, admin_message = _error_code(
        lambda: eb.compose_environments(ApplicationName=app, VersionLabels=[bogus_version])
    )
    assert admin_code == "MissingParameter", (
        f"expected the full-privilege caller to clear the authorization check and instead fail "
        f"with MissingParameter for the nonexistent version label, got {admin_code!r}"
    )
    expected_admin = "No valid application version found."
    assert admin_message == expected_admin, f"expected message {expected_admin!r}, got {admin_message!r}"

    still_no_envs = eb.describe_environments(ApplicationName=app, IncludeDeleted=False)["Environments"]
    assert still_no_envs == [], f"expected no environments after the admin call too, got {still_no_envs!r}"


_CREDENTIAL_PROPAGATION_CODES = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})


def _error_code(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected success raises, so a
    target accepting a call real AWS refuses is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_past_credential_propagation(fn, timeout_s=60.0, interval_s=3.0):
    """A freshly assumed role's credentials can be rejected with InvalidClientTokenId or
    SignatureDoesNotMatch for a few seconds (IAM propagation); retry only that transient class
    and return any other code immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _error_code(fn)
        if code not in _CREDENTIAL_PROPAGATION_CODES:
            return code, message
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"credential propagation never settled within {timeout_s}s; last code {code!r}"
            )
        time.sleep(interval_s)


def _create_app(ctx, eb):
    name = ctx.unique_name("sim2real-eb-app-")
    eb.create_application(
        ApplicationName=name,
        Tags=[{"Key": "sim2real", "Value": "compose-environments-insufficient-privileges-blocked"}],
    )
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=name, TerminateEnvByForce=True))
    return name


def _create_restricted_caller(ctx, allow_actions, deny_statements, name_hint):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name(f"sim2real-eb-restr-{name_hint}-")[:64]
    trust = {
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
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "compose-environments-insufficient-privileges-blocked"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": allow_actions, "Resource": "*"}] + deny_statements,
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="restricted", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="restricted"))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    deadline = time.monotonic() + 60.0
    creds = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-eb")["Credentials"]
            break
        except ClientError:
            time.sleep(3.0)
    if creds is None:
        raise AssertionError("could not assume the restricted-privilege IAM role within 60s")

    client = ctx.client(
        "elasticbeanstalk",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
