"""assume-role-external-id-required-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "assume-role-external-id-required-denied"
GROUP = 'overly-permissive'
SERVICES = ['sts']

_SUCCEEDED = "<call succeeded>"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role trust policy requiring sts:ExternalId denies AssumeRole calls that omit or mismatch it."""

    sts = ctx.client("sts")

    def _error(fn):
        """(code, message) of the error ``fn`` raises; the code is ``_SUCCEEDED``, equal to no AWS
        code, when it succeeds."""
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            if response is not None:
                error = response.get("Error", {})
                return error.get("Code"), error.get("Message")
            return type(exc).__name__, str(exc)
        return _SUCCEEDED, None

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

    def _wait_role_assumable(role_arn, assume_kwargs=None, timeout_s=120, interval_s=3.0):
        kwargs = dict(assume_kwargs or {})

        def probe():
            try:
                sts.assume_role(
                    RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-probe-"), **kwargs
                )
                return True
            except Exception:  # noqa: BLE001
                return False

        _poll_until(
            probe, lambda v: v is True, timeout_s=timeout_s, interval_s=interval_s,
            description=f"role {role_arn} became assumable",
        )

    def _create_assumable_role(trust_policy=None, max_session_duration=3600, inline_policy=None,
                               assume_kwargs=None, expect_assumable=True):
        role_name = ctx.unique_name("sim2real-behav-sts-role-")
        policy = trust_policy if trust_policy is not None else _default_trust_policy()
        resp = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(policy),
            MaxSessionDuration=max_session_duration,
            Tags=_tags_kv(),
        )

        def _drop_role(role_name=role_name):
            try:
                for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                    try:
                        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "NoSuchEntity":
                            raise
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
            try:
                iam.delete_role(RoleName=role_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_drop_role)
        role_arn = resp["Role"]["Arn"]
        if inline_policy is not None:
            iam.put_role_policy(
                RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
            )
        if expect_assumable:
            _wait_role_assumable(role_arn, assume_kwargs=assume_kwargs)
        return role_name, role_arn

    def _trust_policy_for_account(actions=None, extra_condition=None):
        account_id = _account_id()
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": actions if actions is not None else "sts:AssumeRole",
        }
        if extra_condition is not None:
            stmt["Condition"] = extra_condition
        return {"Version": "2012-10-17", "Statement": [stmt]}

    iam = ctx.client("iam")

    expected_external_id = ctx.unique_name("sim2real-behav-extid-")
    trust = _trust_policy_for_account(
        extra_condition={"StringEquals": {"sts:ExternalId": expected_external_id}}
    )
    _role_name, role_arn = _create_assumable_role(trust_policy=trust, expect_assumable=False)

    # expect_assumable=False means the role got no settle wait at all: IAM trust-policy propagation
    # is bounded instead by the poll below, since a fixed sleep cannot reliably outlast it. While it
    # settles AssumeRole may transiently succeed or report a different code -- so poll until the
    # denial STABILIZES instead of asserting single-shot (which flakes). Transient conditions must
    # NOT be latched as the terminal denial: _error falls back to type(exc).__name__ for anything
    # without a botocore response, so a throttle or network blip would satisfy `e[0] != _SUCCEEDED`,
    # end the poll immediately, and fail the AccessDenied assertion as a false negative. Keep
    # polling through these. A divergent *denial* code is deliberately still terminal, so the
    # assertion reports what the target actually said rather than a generic timeout.
    transient = {
        "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException",
        "EndpointConnectionError", "ConnectionError", "ConnectTimeoutError", "ReadTimeoutError",
    }

    def _poll_until_denied(description, **kwargs):
        return _poll_until(
            lambda: _error(
                lambda: sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
                    **kwargs,
                )
            ),
            lambda e: e[0] != _SUCCEEDED and e[0] not in transient,
            timeout_s=60,
            interval_s=3.0,
            description=description,
        )

    caller_arn = sts.get_caller_identity()["Arn"]
    denied = (
        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: "
        f"{role_arn}"
    )

    code_missing, message_missing = _poll_until_denied(
        "trust policy denies AssumeRole with no ExternalId"
    )
    assert code_missing == "AccessDenied", code_missing
    assert message_missing == denied, message_missing

    code_wrong, message_wrong = _poll_until_denied(
        "trust policy denies AssumeRole with the wrong ExternalId",
        ExternalId="not-the-right-id",
    )
    assert code_wrong == "AccessDenied", code_wrong
    assert message_wrong == denied, message_wrong

    # Positive control: without it, a target that denies EVERY AssumeRole (a broken trust
    # evaluator, or a role that was never really created) would pass both denial assertions.
    # The matching ExternalId must be accepted and return real session credentials.
    _wait_role_assumable(role_arn, assume_kwargs={"ExternalId": expected_external_id})
    allowed = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
        ExternalId=expected_external_id,
    )
    assert "Credentials" in allowed, allowed
    assert allowed["Credentials"].get("AccessKeyId"), allowed["Credentials"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
