"""get-caller-identity-reflects-assumed-role-session."""
from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "get-caller-identity-reflects-assumed-role-session"
GROUP = 'credential-issuance'
SERVICES = ['sts']

@tags("axis:happy-path", "cap:unclassified", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCallerIdentity in a session of a role this check assumes returns an Arn of
    arn:aws:sts::<account>:assumed-role/<role>/<session> and a UserId of <roleId>:<session>."""

    sts = ctx.client("sts")

    identity = sts.get_caller_identity()
    assert identity["Account"].isdigit() and len(identity["Account"]) == 12, identity["Account"]
    assert identity["Arn"].startswith("arn:aws:"), identity["Arn"]
    assert f":{identity['Account']}:" in identity["Arn"], identity["Arn"]
    assert identity["UserId"], "UserId must be populated"

    def _client_with_credentials(service, creds):
        return ctx.client(
            service,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds.get("SessionToken"),
            },
        )

    def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description):
        deadline = time.monotonic() + timeout_s
        last = None
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s; last observed: {last!r}"
                )
            time.sleep(interval_s)

    iam = ctx.client("iam")
    account = identity["Account"]
    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _drop_role():
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_drop_role)

    session_name = ctx.unique_name("sim2real-behav-sess-")

    def _try_assume():
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        except Exception:  # noqa: BLE001 - trust-policy propagation, retried below
            return None

    resp = _poll_until(
        _try_assume, lambda r: r is not None,
        timeout_s=120, description=f"role {role_arn} became assumable",
    )

    derived = _client_with_credentials("sts", resp["Credentials"])
    assumed_identity = derived.get_caller_identity()

    # arn:aws:sts::<acct>:assumed-role/<role-name>/<session-name>
    arn = assumed_identity["Arn"]
    assert ":assumed-role/" in arn, (
        f"GetCallerIdentity in an assumed-role session must return an assumed-role ARN; got {arn!r}"
    )
    tail = arn.split(":assumed-role/", 1)[1]
    assert "/" in tail, f"assumed-role ARN must embed a session name: {arn}"
    got_role_name, got_session_name = tail.split("/", 1)
    assert (got_role_name, got_session_name) == (role_name, session_name), (
        f"expected assumed-role ARN for {role_name}/{session_name}; got {arn}"
    )
    assert assumed_identity["UserId"].endswith(f":{session_name}"), (
        f"UserId {assumed_identity['UserId']} must be '<roleId>:{session_name}'"
    )
    assert assumed_identity["Account"] == account, assumed_identity


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
