"""assume-role-trust-policy-principal-restriction-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-trust-policy-principal-restriction-enforced"
GROUP = 'overly-permissive'
SERVICES = ['sts']
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A trust policy naming ONE principal (another role's session) lets that principal assume the
    role, refuses the caller with AccessDenied, and the named principal can still assume it
    afterwards."""

    sts = ctx.client("sts")

    def _make_client_for(service):
        return ctx.client(service)

    def _client_with_credentials(service, creds):
        return ctx.client(service, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    def _error_code(fn):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            if response is not None:
                return response.get("Error", {}).get("Code")
            return type(exc).__name__
        return _OK

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _account_id():
        return sts.get_caller_identity()["Account"]

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _default_trust_policy():
        # Trust the current account root for the three session actions we exercise.
        account_id = _account_id()
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                }
            ],
        }

    def _wait_assumed_credentials(client, role_arn, timeout_s=120, interval_s=3.0):
        # A freshly-created or freshly-named trust relationship is eventually consistent.
        def probe():
            try:
                return client.assume_role(
                    RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-probe-")
                )["Credentials"]
            except Exception:  # noqa: BLE001
                return None

        return _poll_until(
            probe, lambda v: v is not None, timeout_s=timeout_s, interval_s=interval_s,
            description=f"role {role_arn} became assumable",
        )

    def _create_role(trust_policy, inline_policy=None, max_session_duration=3600):
        role_name = ctx.unique_name("sim2real-behav-sts-role-")
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            MaxSessionDuration=max_session_duration,
            Tags=_tags_kv(),
        )

        def _drop_role(role_name=role_name):
            # NoSuchEntity means the role or policy is already gone; anything else is a real failure.
            try:
                for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                    try:
                        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
                    except iam.exceptions.NoSuchEntityException:
                        pass
                iam.delete_role(RoleName=role_name)
            except iam.exceptions.NoSuchEntityException:
                pass

        ctx.on_cleanup(_drop_role)
        role_arn = resp["Role"]["Arn"]
        if inline_policy is not None:
            iam.put_role_policy(
                RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
            )
        return role_name, role_arn

    def _allow_all_policy():
        return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}

    iam = _make_client_for("iam")

    # The named principal: a role the caller can assume, whose allow-all identity policy lets
    # its session call sts:AssumeRole.
    _other_name, other_arn = _create_role(_default_trust_policy(), inline_policy=_allow_all_policy())
    other_creds = _wait_assumed_credentials(sts, other_arn)
    other_sts = _client_with_credentials("sts", other_creds)

    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": other_arn},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    _role_name, role_arn = _create_role(trust, inline_policy=_allow_all_policy())

    # Positive control: separates "the caller is denied" from "the role is unassumable".
    positive_creds = _wait_assumed_credentials(other_sts, role_arn, timeout_s=90)
    assert positive_creds.get("AccessKeyId"), (
        f"the session assumed from {other_arn!r} is the one principal {role_arn!r} trusts and "
        "must be able to assume it"
    )

    # The identical call as the caller, who is named nowhere in the trust policy.
    refusal = {}

    def _assume_as_caller():
        try:
            sts.assume_role(RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-"))
        except ClientError as exc:
            refusal["message"] = exc.response.get("Error", {}).get("Message")
            raise

    code = _poll_until(
        lambda: _error_code(_assume_as_caller),
        lambda c: c == "AccessDenied",
        timeout_s=90,
        interval_s=3.0,
        description="trust policy denies the non-listed principal",
    )
    assert code == "AccessDenied", (
        f"a role trusting only {other_arn} must not be assumable by anyone else, got code={code!r}"
    )
    assert refusal.get("message") == (
        f"User: {sts.get_caller_identity()['Arn']} is not authorized to perform: sts:AssumeRole "
        f"on resource: {role_arn}"
    ), refusal.get("message")

    # The named principal's access survives: a principal-specific restriction, not a shared
    # rate limit or a poisoned cache.
    still_creds = _wait_assumed_credentials(other_sts, role_arn, timeout_s=60)
    assert still_creds.get("AccessKeyId"), (
        f"{other_arn!r} must still be able to assume {role_arn!r} after the caller's denial"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
