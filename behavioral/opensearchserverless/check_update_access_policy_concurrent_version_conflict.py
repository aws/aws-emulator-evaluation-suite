"""update-access-policy-concurrent-version-conflict."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "update-access-policy-concurrent-version-conflict"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Five concurrent UpdateAccessPolicy calls against the same policyVersion leave exactly one winner,
    whose version and principal GetAccessPolicy then returns; the other four fail with
    ValidationException and the exact stale-version message."""
    osc = ctx.client("opensearchserverless")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = _short_name(ctx, "sim2real-racepol-")

    base_policy = [
        {
            "Rules": [{"ResourceType": "collection", "Resource": ["collection/base*"], "Permission": ["aoss:*"]}],
            "Principal": [f"arn:aws:iam::{account_id}:role/base-role"],
        }
    ]
    created = osc.create_access_policy(type="data", name=name, policy=json.dumps(base_policy))
    stale_version = created["accessPolicyDetail"]["policyVersion"]
    ctx.on_cleanup(lambda: osc.delete_access_policy(type="data", name=name))

    n_racers = 5

    def _racer(i):
        policy = [
            {
                "Rules": [
                    {"ResourceType": "collection", "Resource": [f"collection/racer{i}*"], "Permission": ["aoss:*"]}
                ],
                "Principal": [f"arn:aws:iam::{account_id}:role/racer{i}-role"],
            }
        ]
        try:
            resp = osc.update_access_policy(
                type="data", name=name, policyVersion=stale_version, policy=json.dumps(policy)
            )
            return ("ok", i, resp["accessPolicyDetail"]["policyVersion"])
        except Exception as exc:  # noqa: BLE001 - classified below via error code
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", i, (exc.response["Error"]["Code"], exc.response["Error"]["Message"]))
            raise

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_racer, i) for i in range(n_racers)]
        results = [f.result() for f in as_completed(futures)]

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "error"]

    assert len(winners) == 1, f"expected exactly one racer to win the optimistic update, got {winners!r}"
    assert len(losers) == n_racers - 1, f"expected {n_racers - 1} losers, got {losers!r}"
    stale = "Policy version specified in the request refers to an older version and policy has since changed"
    for _, _, (code, message) in losers:
        # OpenSearch Serverless refuses a stale policyVersion with ValidationException, not ConflictException.
        assert code == "ValidationException", (
            f"expected ValidationException for a stale-version loser, got {code!r}"
        )
        assert message == stale, f"expected message {stale!r}, got {message!r}"

    winner_index = winners[0][1]
    winner_version = winners[0][2]
    final = osc.get_access_policy(type="data", name=name)["accessPolicyDetail"]
    assert final["policyVersion"] == winner_version, "stored policyVersion doesn't match the declared winner"
    assert final["policy"][0]["Principal"] == [f"arn:aws:iam::{account_id}:role/racer{winner_index}-role"], (
        f"stored policy content doesn't match the declared winner's submission: {final['policy']!r}"
    )


def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
