"""cli-dynamodb-create-table-put-item-scan-roundtrip."""
from __future__ import annotations

import json
import subprocess

from behavioral_harness import tags

CHECK = "cli-dynamodb-create-table-put-item-scan-roundtrip"
GROUP = "cli-roundtrip"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI create-table + put-item + scan roundtrip: the scanned items exactly match the
    typed attribute values written via the CLI, and a targeted get-item returns the same
    typed value (proving the CLI writes landed in the real data plane, not just accepted)."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    table_name = ctx.unique_name("sim2real-tbl-")
    ddb = ctx.client("dynamodb")
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))

    _run_aws(
        ctx, "dynamodb", "create-table", "--table-name", table_name,
        "--attribute-definitions", "AttributeName=pk,AttributeType=S",
        "--key-schema", "AttributeName=pk,KeyType=HASH",
        "--billing-mode", "PAY_PER_REQUEST",
        "--tags", f"Key=sim2real,Value={CHECK}",
    )
    _run_aws(ctx, "dynamodb", "wait", "table-exists", "--table-name", table_name)

    items = {
        "item-1": {"pk": {"S": "item-1"}, "score": {"N": "42"}, "tag": {"S": "alpha"}},
        "item-2": {"pk": {"S": "item-2"}, "score": {"N": "7"}, "tag": {"S": "beta"}},
        "item-3": {"pk": {"S": "item-3"}, "score": {"N": "99"}, "tag": {"S": "gamma"}},
    }
    for item in items.values():
        _run_aws(ctx, "dynamodb", "put-item", "--table-name", table_name, "--item", json.dumps(item))

    scan_result = _run_aws(ctx, "dynamodb", "scan", "--table-name", table_name)
    scanned = {i["pk"]["S"]: i for i in scan_result["Items"]}
    assert scanned.keys() == items.keys(), (
        f"scan returned a different item set: {sorted(scanned.keys())} != {sorted(items.keys())}"
    )
    for key, expected in items.items():
        assert scanned[key] == expected, f"item {key} mismatch: {scanned[key]} != {expected}"

    get_result = _run_aws(
        ctx, "dynamodb", "get-item", "--table-name", table_name,
        "--key", json.dumps({"pk": {"S": "item-2"}}),
    )
    assert get_result["Item"] == items["item-2"], (
        f"get-item returned {get_result.get('Item')} != {items['item-2']}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env, capture_output=True,
        text=True, timeout=timeout_s, cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
