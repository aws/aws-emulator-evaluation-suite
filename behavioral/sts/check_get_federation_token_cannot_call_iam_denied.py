"""get-federation-token-cannot-call-iam-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-cannot-call-iam-denied"
GROUP = 'overly-permissive'
SERVICES = ['sts']


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A federated session with an allow-all policy can list S3 buckets but IAM rejects it with
    InvalidClientTokenId and the exact message: the credential type is refused at authentication."""

    sts = ctx.client("sts")

    def _client_with_credentials(service, creds):
        return ctx.client(
            service,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds.get("SessionToken"),
            },
        )

    def _error(fn):
        """fn()'s error (code, message); a success raises because the call must be refused."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")

    def _allow_all_policy():
        return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}

    def _wait_creds_active(creds, *, timeout_s=120.0, interval_s=2.0):
        # Freshly minted temporary credentials are eventually consistent; GetCallerIdentity
        # needs no permissions, so it is a safe liveness probe.
        probe = _client_with_credentials("sts", creds)
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                probe.get_caller_identity()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"federated session credentials never became active within {timeout_s}s "
                    f"(last code={code!r})"
                )
            time.sleep(interval_s)

    fed_name = ctx.unique_name("sim2real-behav-fed-")[:32]
    resp = sts.get_federation_token(Name=fed_name, Policy=json.dumps(_allow_all_policy()))
    creds = resp["Credentials"]
    _wait_creds_active(creds)

    # Control: the session is live and its policy is honored outside IAM.
    scoped_s3 = _client_with_credentials("s3", creds)
    scoped_s3.list_buckets()

    scoped_iam = _client_with_credentials("iam", creds)
    code, message = _error(lambda: scoped_iam.list_users())
    assert code == "InvalidClientTokenId", (
        f"GetFederationToken sessions must never be able to call IAM APIs, got code={code!r}"
    )
    assert message == "The security token included in the request is invalid", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
