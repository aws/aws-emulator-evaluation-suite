"""deep-cognito-identity-1-unsigned-public-api-delete-identities-rejected."""
from __future__ import annotations

import time

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-identity-1-unsigned-public-api-delete-identities-rejected"
GROUP = "unsigned-public-api"
SERVICES = ["cognito-identity"]

# On real Cognito Identity, UNSIGNED DeleteIdentities and
# DeleteIdentityPool are both refused MissingAuthenticationTokenException (HTTP 400) — even for an
# identity the same unsigned client just minted with GetId. The model declares neither code.
ERR_UNSIGNED = "MissingAuthenticationTokenException"
MSG_UNSIGNED = "Missing Authentication Token"
ERR_NOT_FOUND = "ResourceNotFoundException"


@tags("dp:api", "plane:data", "concern:negative-classes", "axis:rejection", "cap:c1")
def run(ctx) -> None:
    """An unsigned caller can mint identities but is refused deleting them or the pool, and both
    stay fully usable afterwards; the same deletes succeed once signed and the identity is then
    gone for the public API too."""
    signed = ctx.client("cognito-identity")
    unsigned = ctx.client("cognito-identity", config=Config(signature_version=UNSIGNED))

    pool_id = signed.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-unsigned-pool-").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": GROUP},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: signed.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = unsigned.get_id(IdentityPoolId=pool_id)["IdentityId"]

    err = _error(lambda: unsigned.delete_identities(IdentityIdsToDelete=[identity_id]))
    assert (err.get("Code"), err.get("Message")) == (ERR_UNSIGNED, MSG_UNSIGNED), (
        f"unsigned DeleteIdentities answered {err!r}, expected {ERR_UNSIGNED!r}"
    )
    err = _error(lambda: unsigned.delete_identity_pool(IdentityPoolId=pool_id))
    assert (err.get("Code"), err.get("Message")) == (ERR_UNSIGNED, MSG_UNSIGNED), (
        f"unsigned DeleteIdentityPool answered {err!r}, expected {ERR_UNSIGNED!r}"
    )

    # Effect absent: the pool and the identity both survived, and stay usable unsigned.
    pool = signed.describe_identity_pool(IdentityPoolId=pool_id)
    assert pool["IdentityPoolId"] == pool_id, f"pool now describes as {pool['IdentityPoolId']!r}"
    ident = signed.describe_identity(IdentityId=identity_id)
    assert ident["IdentityId"] == identity_id, f"identity now describes as {ident['IdentityId']!r}"
    token = unsigned.get_open_id_token(IdentityId=identity_id)
    assert token["IdentityId"] == identity_id and token.get("Token"), (
        f"unsigned GetOpenIdToken after the refused delete returned "
        f"{token['IdentityId']!r} with token present={bool(token.get('Token'))!r}"
    )

    # Positive control: the same delete, signed, succeeds and really removes the identity.
    deleted = signed.delete_identities(IdentityIdsToDelete=[identity_id])
    assert deleted.get("UnprocessedIdentityIds") == [], (
        f"signed DeleteIdentities left {deleted.get('UnprocessedIdentityIds')!r} unprocessed"
    )
    not_found = (ERR_NOT_FOUND, f"Identity '{identity_id}' not found.")
    err = _poll_for_error(
        lambda: signed.describe_identity(IdentityId=identity_id), timeout_s=60.0, interval_s=2.0,
    )
    assert (err.get("Code"), err.get("Message")) == not_found, f"signed DescribeIdentity after delete answered {err!r}"
    err = _error(lambda: unsigned.get_open_id_token(IdentityId=identity_id))
    assert (err.get("Code"), err.get("Message")) == not_found, (
        f"unsigned GetOpenIdToken for the deleted identity answered {err!r}, expected {not_found!r}"
    )


# ===== helpers =====

def _error(fn):
    """The ClientError fn() raised (Code, Message). A success is never an error: it raises instead."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    resp.pop("ResponseMetadata", None)
    raise AssertionError(f"call was expected to be refused but succeeded: {resp!r}")


def _poll_for_error(fn, *, timeout_s, interval_s):
    """Poll fn() until it raises; return that error. Still succeeding at the deadline is a FAIL."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {})
        if time.monotonic() >= deadline:
            raise AssertionError(f"call still succeeded after {timeout_s}s; the delete did not take")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
