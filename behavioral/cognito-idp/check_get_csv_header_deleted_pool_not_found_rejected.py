"""get-csv-header-deleted-pool-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-csv-header-deleted-pool-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCSVHeader on a just-deleted pool fails with ResourceNotFoundException and its exact message,
    while a live pool returns a non-empty header with a name column."""
    cip = ctx.client("cognito-idp")
    live_pool = _create_pool(ctx)

    doomed_pool = cip.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog"},
    )["UserPool"]["Id"]
    cip.delete_user_pool(UserPoolId=doomed_pool)

    code = _error(lambda: cip.get_csv_header(UserPoolId=doomed_pool))
    assert code == ("ResourceNotFoundException", f"User pool {doomed_pool} does not exist."), (
        f"expected ResourceNotFoundException, got {code!r}"
    )

    # positive control: a live pool still returns a real CSV header
    header = cip.get_csv_header(UserPoolId=live_pool)
    assert header["CSVHeader"], "expected a non-empty CSV header for a live pool"
    assert any("name" in col for col in header["CSVHeader"]), header["CSVHeader"]


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_pool(ctx):
    cip = ctx.client("cognito-idp")
    pool_id = cip.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
