"""assume-role-malformed-session-policy-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-malformed-session-policy-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A syntactically invalid AssumeRole session Policy document is rejected with MalformedPolicyDocument."""

    sts = ctx.client("sts")

    def _refusal(fn):
        """(code, message) of the error ``fn`` raises; AssertionError when it succeeds."""
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")

    def _stable_refusal(fn, transient=(), attempts=8, interval_s=3.0):
        """``_refusal`` retried while its code is one of ``transient``."""
        last = None
        for _ in range(attempts):
            last = _refusal(fn)
            if last[0] not in transient:
                return last
            time.sleep(interval_s)
        return last

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

    def _wait_role_assumable(role_arn, timeout_s=120, interval_s=3.0):
        def probe():
            try:
                sts.assume_role(RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-probe-"))
                return True
            except Exception:  # noqa: BLE001
                return False

        _poll_until(
            probe, lambda v: v is True, timeout_s=timeout_s, interval_s=interval_s,
            description=f"role {role_arn} became assumable",
        )

    def _create_assumable_role():
        role_name = ctx.unique_name("sim2real-behav-sts-role-")
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(_default_trust_policy()),
            Tags=_tags_kv(),
        )

        def _drop_role(role_name=role_name):
            try:
                iam.delete_role(RoleName=role_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_drop_role)
        role_arn = resp["Role"]["Arn"]
        # Positive control: a freshly-created trust policy is eventually consistent, so
        # confirm the role is genuinely assumable before using it to test the malformed
        # policy claim -- otherwise "rejects a malformed policy" is indistinguishable
        # from "rejects every AssumeRole".
        _wait_role_assumable(role_arn)
        return role_name, role_arn

    iam = ctx.client("iam")

    _role_name, role_arn = _create_assumable_role()
    session_name = ctx.unique_name("sim2real-behav-sess-")

    code, message = _stable_refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            Policy="{this is not valid json",
        ),
        transient=("AccessDenied", "InvalidClientTokenId"),
    )
    assert code == "MalformedPolicyDocument", (
        f"expected MalformedPolicyDocument for a syntactically invalid session Policy, got {code}"
    )
    assert message == (
        "Unexpected IOException: Unexpected character ('t' (code 116)): was expecting "
        "double-quote to start field name\n at [Source: REDACTED "
        "(`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: 2]"
    ), message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
