"""concurrent-pack-creation-same-name-no-corruption."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-pack-creation-same-name-no-corruption"
GROUP = "concurrency"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Six concurrent CreateSecurityRequirementPack calls with one name yield at least two distinct
    packIds, each gettable by its id and listed exactly once under that name; the only failure allowed
    is the concurrent-operations-limit ValidationException, never a name conflict."""
    sa = ctx.client("securityagent")
    name = ctx.unique_name("sim2real-behav-race-pack-")
    racers = 6

    def _attempt():
        try:
            pack_id = sa.create_security_requirement_pack(
                name=name, tags={"purpose": "sim2real"}
            )["packId"]
            return ("ok", pack_id)
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_attempt) for _ in range(racers)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r[1] for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]

    # a uniqueness-enforcing target can let at most one racer through; two independent
    # winners under the identical name directly refutes that, which "at least one" cannot
    assert len(successes) >= 2, (
        f"expected at least 2 of {racers} racers to win under the identical name (no "
        f"name-uniqueness enforcement), got {len(successes)}: {results}"
    )
    assert len(successes) == len(set(successes)), f"packIds are not all distinct: {successes}"

    for _, code, message in errors:
        is_concurrency_limit = (
            code == "ValidationException"
            and message
            and "concurrent operations limit" in message.lower()
        )
        assert is_concurrency_limit, (
            f"racer failed with {code}: {message!r}, expected only the account's concurrent-"
            f"operations-limit ValidationException — anything else (e.g. a name conflict) "
            f"means uniqueness is being enforced"
        )

    for pack_id in successes:
        ctx.on_cleanup(lambda pid=pack_id: sa.delete_security_requirement_pack(packId=pid))

    # no corruption: every winner is independently gettable by its own packId with the
    # right name, and appears exactly once in the list under that name
    for pack_id in successes:
        got = sa.get_security_requirement_pack(packId=pack_id)
        assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
        assert got["packId"] == pack_id, f"expected packId {pack_id!r}, got {got['packId']!r}"

    matches = [
        p
        for p in sa.list_security_requirement_packs()["securityRequirementPackSummaries"]
        if p["name"] == name
    ]
    assert {p["packId"] for p in matches} == set(successes), (
        f"listed packs under name {name!r} ({[p['packId'] for p in matches]}) don't match "
        f"the racers that reported success ({successes})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

