"""concurrent-invalid-token-requests-all-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-invalid-token-requests-all-rejected"
GROUP = "concurrency"
SERVICES = ["sso"]
MESSAGE = "Session token not found or invalid"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Ten concurrent GetRoleCredentials calls with the same invalid bearer token are all rejected with
    UnauthorizedException and the exact message: authentication is a per-request gate that no
    concurrent request slips through."""
    sso = ctx.client("sso")
    bogus_token = f"sim2real-bogus-{ctx.unique_name('tok')}"

    def call():
        return _error(
            lambda: sso.get_role_credentials(
                roleName="AdministratorAccess",
                accountId="111122223333",
                accessToken=bogus_token,
            )
        )

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(call) for _ in range(10)]
        errors = [f.result() for f in as_completed(futures)]

    assert len(errors) == 10
    for code, message in errors:
        assert code == "UnauthorizedException", (
            f"expected all 10 concurrent calls rejected with UnauthorizedException, got {errors}"
        )
        assert message == MESSAGE, f"expected all 10 messages {MESSAGE!r}, got {errors}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this bogus bearer token, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
