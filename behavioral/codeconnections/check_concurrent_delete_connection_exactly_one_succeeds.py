"""concurrent-delete-connection-exactly-one-succeeds."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-delete-connection-exactly-one-succeeds"
GROUP = "concurrency"
SERVICES = ["codeconnections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent DeleteConnection calls on one connection: at least one and fewer than all succeed,
    every loser gets ResourceNotFoundException with the exact message, and GetConnection then reports
    the connection gone."""
    from botocore.exceptions import ClientError

    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2realcc-")[-32:]
    conn_arn = cc.create_connection(
        ConnectionName=name,
        ProviderType="GitHub",
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["ConnectionArn"]

    def _safe_delete_if_present():
        from botocore.exceptions import ClientError as _CE

        try:
            cc.delete_connection(ConnectionArn=conn_arn)
        except _CE as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_safe_delete_if_present)

    def _racer(_i: int):
        try:
            cc.delete_connection(ConnectionArn=conn_arn)
            return ("ok", None)
        except ClientError as err:
            return ("error", (err.response["Error"]["Code"], err.response["Error"].get("Message")))

    n_racers = 8
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(_racer, range(n_racers)))

    successes = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]

    assert 1 <= len(successes) < n_racers, (
        f"expected at least one winner and at least one loser among {n_racers} racers, "
        f"got {len(successes)} winners: {results}"
    )
    assert len(errors) == n_racers - len(successes), f"successes/errors don't partition the racers: {results}"
    assert all(code == "ResourceNotFoundException" for _, (code, _msg) in errors), (
        f"every losing racer must see ResourceNotFoundException, got codes {[c for _, (c, _m) in errors]}"
    )
    expected = "No connection exists with the ARN"
    assert all(msg == expected for _, (_code, msg) in errors), (
        f"every losing racer must see message {expected!r}, got {[m for _, (_c, m) in errors]}"
    )

    # Independent terminal read, through a different operation than any racer used to
    # mutate: the connection must be durably gone, not just momentarily unavailable to
    # the losing racers.
    try:
        cc.get_connection(ConnectionArn=conn_arn)
        raise AssertionError("expected GetConnection on the deleted arn to raise ResourceNotFoundException")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected GetConnection on the deleted arn to report ResourceNotFoundException, got {code}"
        )
        message = err.response["Error"].get("Message")
        expected = "No connection exists with the ARN"
        assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
