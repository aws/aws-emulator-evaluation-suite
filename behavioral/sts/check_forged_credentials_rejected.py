"""forged-credentials-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "forged-credentials-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sts']

@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Syntactically valid but never-issued credentials must be rejected by the auth layer."""

    def _forged_client(service="sts"):
        # Syntactically plausible but never-issued credentials.
        return ctx.client(service, creds={
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        })

    def _rejection(fn):
        # An unexpected SUCCESS raises.
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"forged credentials were ACCEPTED, returned {result!r}")

    # Positive control: the identical call, on the same wiring, with the runner's own
    # credentials must succeed -- otherwise a forged-credential rejection below is
    # indistinguishable from an unreachable or broken STS endpoint.
    identity = ctx.client("sts").get_caller_identity()
    assert identity.get("Account"), f"positive control failed: {identity!r}"

    client = _forged_client("sts")
    code, message = _rejection(lambda: client.get_caller_identity())
    assert code == "InvalidClientTokenId", f"expected credential rejection, got {code}"
    assert message == "The security token included in the request is invalid.", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
