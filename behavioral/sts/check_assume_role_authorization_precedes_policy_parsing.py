"""assume-role-authorization-precedes-policy-parsing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-authorization-precedes-policy-parsing"
GROUP = 'error-semantics'
SERVICES = ['sts']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRole authorizes before parsing the session policy: a malformed Policy on an
    unassumable role gives AccessDenied, while on an assumable role it gives
    MalformedPolicyDocument (so the denial is not unconditional)."""

    sts = ctx.client("sts")
    iam = ctx.client("iam")

    MALFORMED_POLICY = "{not valid json"

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

    def _account_id():
        return sts.get_caller_identity()["Account"]

    def _nonexistent_role_arn(account_id=None):
        # Well-formed ARN that refers to no real role: passes ARN pattern validation but
        # can never authorize, the right substitute for negative AssumeRole assertions.
        acct = account_id or _account_id()
        return f"arn:aws:iam::{acct}:role/{ctx.unique_name('sim2real-behav-no-such-role-')}"

    def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    account_id = _account_id()
    role_name = ctx.unique_name("sim2real-behav-sts-ordering-")
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    role_arn = resp["Role"]["Arn"]

    def _drop_role(role_name=role_name):
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_drop_role)

    # Positive control: a freshly-created trust policy is eventually consistent, so
    # confirm the role is genuinely assumable before using it to test the ordering claim.
    def _probe():
        try:
            sts.assume_role(RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-probe-"))
            return True
        except Exception:  # noqa: BLE001
            return False

    _poll_until(_probe, lambda ok: ok is True, description=f"role {role_arn} became assumable")

    # Break exactly the policy, holding the role valid: an authorized caller with the SAME
    # malformed policy must fail parsing, not authorization -- proving parsing is real and
    # reachable rather than the target unconditionally denying rejected calls.
    parse_code, parse_message = _stable_refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            Policy=MALFORMED_POLICY,
        ),
        transient=("AccessDenied", "InvalidClientTokenId"),
    )
    assert parse_code == "MalformedPolicyDocument", (
        "an authorized role with a malformed session policy must fail parsing: "
        f"expected MalformedPolicyDocument, got {parse_code}"
    )
    assert parse_message == (
        "Unexpected IOException: Unexpected character ('n' (code 110)): was expecting "
        "double-quote to start field name\n at [Source: REDACTED "
        "(`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1, column: 2]"
    ), parse_message

    # Break exactly the authorization, holding the SAME malformed policy fixed: real STS
    # returns AccessDenied here instead of MalformedPolicyDocument, proving authorization
    # is evaluated before session-policy parsing.
    caller_arn = sts.get_caller_identity()["Arn"]
    denied_arn = _nonexistent_role_arn(account_id)
    denied_code, denied_message = _refusal(
        lambda: sts.assume_role(
            RoleArn=denied_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            Policy=MALFORMED_POLICY,
        )
    )
    assert denied_code == "AccessDenied", (
        "authorization must be evaluated before session-policy parsing: "
        f"expected AccessDenied, got {denied_code}"
    )
    assert denied_message == (
        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: "
        f"{denied_arn}"
    ), denied_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
