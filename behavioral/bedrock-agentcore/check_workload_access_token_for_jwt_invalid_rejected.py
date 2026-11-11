"""workload-access-token-for-jwt-invalid-rejected."""
from __future__ import annotations

import base64
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workload-access-token-for-jwt-invalid-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetWorkloadAccessTokenForJWT refuses a well-formed but unsigned, expired JWT with
    UnauthorizedException ('Token has expired'), while GetWorkloadAccessToken for the same workload
    identity still mints a token.
    """
    control = ctx.client("bedrock-agentcore-control")
    agentcore = ctx.client("bedrock-agentcore")

    workload_name = ("simreal-wat-jwt-" + uuid.uuid4().hex)[:60]
    control.create_workload_identity(name=workload_name)
    ctx.on_cleanup(
        lambda: _safe(lambda: control.delete_workload_identity(name=workload_name))
    )

    fake_jwt = _fake_expired_jwt()
    code, message = _error(
        lambda: agentcore.get_workload_access_token_for_jwt(
            workloadName=workload_name, userToken=fake_jwt
        )
    )
    assert code == "UnauthorizedException", f"expected UnauthorizedException, got {code}"
    assert message == "Token has expired", f"expected the exact expired-token message, got {message!r}"

    # Positive control: the same workload identity is otherwise fully functional.
    control_resp = agentcore.get_workload_access_token(workloadName=workload_name)
    assert len(control_resp["workloadAccessToken"]) > 0


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _b64url(payload: dict) -> str:
    raw = json.dumps(payload).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _fake_expired_jwt() -> str:
    header = _b64url({"alg": "HS256", "typ": "JWT"})
    payload = _b64url(
        {
            "iss": "https://sim2real.invalid/",
            "sub": "sim2real-test-user",
            "exp": int(time.time()) - 3600,
        }
    )
    signature = "c2ltMnJlYWxmYWtlc2ln"  # not a valid signature; three-segment JWT shape only
    return f"{header}.{payload}.{signature}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
