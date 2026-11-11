"""decode-authorization-message-rejects-realistic-fake-blob."""
from __future__ import annotations

import base64
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "decode-authorization-message-rejects-realistic-fake-blob"
GROUP = 'error-semantics'
SERVICES = ['sts']



@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A long base64url blob shaped like a genuine encoded message is rejected with
    InvalidAuthorizationMessageException, so only real integrity checking can refuse it."""

    sts = ctx.client("sts")

    def _error(fn):
        """The (code, message) of the refusal ``fn`` raises; raises AssertionError on success."""
        try:
            resp = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected a refusal, but the fake blob decoded: {resp!r}")

    blob = "".join(
        base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")
        for _ in range(24)
    )
    assert len(blob) > 400, len(blob)

    refusal = _error(
        lambda: sts.decode_authorization_message(EncodedMessage=blob)
    )
    # STS echoes the base64-decoded payload back as signed bytes.
    raw = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
    expected = "Message is not valid: [" + ", ".join(str(b - 256 if b > 127 else b) for b in raw) + "]"
    assert refusal == ("InvalidAuthorizationMessageException", expected), (refusal, expected)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
