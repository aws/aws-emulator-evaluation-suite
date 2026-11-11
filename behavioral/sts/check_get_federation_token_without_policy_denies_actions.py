"""get-federation-token-without-policy-denies-actions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-without-policy-denies-actions"
GROUP = 'overly-permissive'
SERVICES = ['sts']

# New temporary credentials are eventually consistent and can be rejected with these codes for
# several seconds regardless of policy; they are retried, never asserted.
_PROPAGATION_TRANSIENTS = ("InvalidClientTokenId", "InvalidAccessKeyId")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A policy-less GetFederationToken session is refused s3:ListAllMyBuckets with AccessDenied,
    and the identical call on a token carrying an allow policy succeeds."""

    sts = ctx.client("sts")
    s3 = ctx.client("s3")

    def _client_with_credentials(service, creds):
        return ctx.client(service, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s; last observed {last!r}"
                )
            time.sleep(interval_s)

    def _stable_denial(fn, *, timeout_s=90.0):
        """Poll fn() past propagation transients; returns the refusal's (code, message).
        Raises the moment fn() succeeds, so a success never hides behind a code mismatch."""

        def probe():
            try:
                result = fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                return err.get("Code"), err.get("Message")
            raise AssertionError(
                f"expected the policy-less federation token to be refused, but the call "
                f"SUCCEEDED and returned {result!r}"
            )

        return _poll(
            probe, lambda r: r[0] not in _PROPAGATION_TRANSIENTS, timeout_s=timeout_s,
            description="error code stabilises past credential propagation",
        )

    def _stable_success(fn, *, what="call", timeout_s=90.0):
        """Poll fn() until it succeeds. Raises immediately on a non-transient denial --
        a positive control must fail loudly, not time out silently."""

        def probe():
            try:
                fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in _PROPAGATION_TRANSIENTS:
                    return code
                raise AssertionError(
                    f"expected {what} to be permitted by the supplied Policy, got {code!r}"
                ) from exc
            return None

        return _poll(probe, lambda c: c is None, timeout_s=timeout_s, description=f"{what} became permitted")

    # Positive control: the ambient caller has s3 access, so a later denial is the policy's.
    try:
        s3.list_buckets()
    except ClientError as exc:
        raise AssertionError(
            "positive control failed: the ambient caller could not list its own buckets "
            f"({exc.response.get('Error', {}).get('Code')!r}); cannot attribute a later "
            "denial to the federation token's missing policy"
        ) from exc

    name = ctx.unique_name("sim2real-behav-fed-")
    resp = sts.get_federation_token(Name=name, DurationSeconds=900)
    fed_s3 = _client_with_credentials("s3", resp["Credentials"])
    fed_arn = resp["FederatedUser"]["Arn"]

    # S3 rather than IAM: federation sessions can never call IAM, so an IAM refusal would not
    # show that permissions derive from the missing policy.
    code, message = _stable_denial(lambda: fed_s3.list_buckets())
    assert code == "AccessDenied", (
        "expected a policy-less federation token to be refused s3:ListAllMyBuckets with "
        f"AccessDenied, got {code!r}"
    )
    expected_message = (
        f"User: {fed_arn} is not authorized to perform: s3:ListAllMyBuckets "
        "because no session policy allows the s3:ListAllMyBuckets action"
    )
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    # The identical call on a token whose Policy allows it must succeed.
    allow_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    })
    restored = sts.get_federation_token(
        Name=ctx.unique_name("sim2real-behav-fed-"), Policy=allow_policy, DurationSeconds=900,
    )
    fed_s3_restored = _client_with_credentials("s3", restored["Credentials"])
    _stable_success(
        lambda: fed_s3_restored.list_buckets(),
        what="s3:ListAllMyBuckets allowed by the supplied Policy",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
