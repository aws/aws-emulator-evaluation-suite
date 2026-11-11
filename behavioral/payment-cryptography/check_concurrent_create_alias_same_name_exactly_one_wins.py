"""concurrent-create-alias-same-name-exactly-one-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-alias-same-name-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["payment-cryptography"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateAlias calls for one AliasName on different keys leave at least one success,
    every refused racer gets ConflictException with the exact message, and the alias points at a key a
    successful racer requested, unchanged on a second read."""
    pc = ctx.client("payment-cryptography")
    n = 5
    keys = [_create_key(ctx, pc) for _ in range(n)]
    alias_name = "alias/" + ctx.unique_name("sim2real-pc-race-").rstrip("-")
    ctx.on_cleanup(lambda: _safe_delete_alias(pc, alias_name))

    def _attempt(key_arn: str):
        try:
            pc.create_alias(AliasName=alias_name, KeyArn=key_arn)
            return ("ok", key_arn, None)
        except Exception as e:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                return ("error", key_arn, e.response["Error"]["Code"], e.response["Error"].get("Message"))
            raise

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(_attempt, [k["KeyArn"] for k in keys]))

    successes = [r[:3] for r in results if r[0] == "ok"]
    failures = [r[:3] for r in results if r[0] == "error"]
    messages = [r[3] for r in results if r[0] == "error"]

    assert successes, f"expected at least one winner among {n} racers, got none: {results}"
    assert len(successes) + len(failures) == n, (
        f"expected every racer to resolve ok or error, got {results}"
    )
    assert all(code == "ConflictException" for (_, _, code) in failures), (
        f"expected every loser to get ConflictException, got codes: {[c for (_, _, c) in failures]}"
    )
    expected = f"Alias {alias_name} already exists."
    assert all(m == expected for m in messages), (
        f"expected every loser's message to be {expected!r}, got {messages!r}"
    )

    winner_key_arns = {key_arn for (_, key_arn, _) in successes}
    final = pc.get_alias(AliasName=alias_name)["Alias"]
    assert final["KeyArn"] in winner_key_arns, (
        f"expected the alias to converge to one of the racers that got a success response "
        f"{sorted(winner_key_arns)}, got {final['KeyArn']} (a losing or phantom key here would mean "
        f"the ConflictException some racers received does not reliably prevent a corrupted binding)"
    )

    for _ in range(3):
        reread = pc.get_alias(AliasName=alias_name)["Alias"]
        assert reread["KeyArn"] == final["KeyArn"], (
            f"expected the converged alias binding to be stable once observed, "
            f"first read {final['KeyArn']!r} then {reread['KeyArn']!r}"
        )


def _create_key(ctx, pc):
    key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    key = pc.create_key(
        KeyAttributes=key_attributes,
        Exportable=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Key"]
    arn = key["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))
    return key


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_alias(pc, alias_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_alias(AliasName=alias_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
