"""api-key-credential-provider-concurrent-create-name-uniqueness."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-key-credential-provider-concurrent-create-name-uniqueness"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Six concurrent CreateApiKeyCredentialProvider calls on one name yield exactly one success and five
    ConflictException or ValidationException refusals, and the provider then reads back under that name."""
    control = ctx.client("bedrock-agentcore-control")
    name = ctx.unique_name("sim2real-apikeycp-race-")
    tags_map = {"sim2real-check": "api-key-credential-provider-concurrent-create-name-uniqueness"}
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: control.delete_api_key_credential_provider(name=name))
    )

    racers = 6

    def _attempt(i):
        try:
            control.create_api_key_credential_provider(
                name=name, apiKey=f"sk-sim2real-race-{i}", tags=tags_map
            )
            return "ok"
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            # Real AWS enforces name uniqueness atomically, but the exact error
            # code observed for the racing losers is ValidationException (not
            # ConflictException) — the service treats a duplicate name as an
            # input-validation failure rather than a resource conflict.
            if code in ("ConflictException", "ValidationException"):
                return "conflict"
            raise

    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_attempt, i) for i in range(racers)]
        outcomes = [f.result() for f in as_completed(futures)]

    assert outcomes.count("ok") == 1, f"expected exactly 1 winner, got outcomes={outcomes}"
    assert outcomes.count("conflict") == racers - 1, (
        f"expected {racers - 1} racers to lose the race, got outcomes={outcomes}"
    )

    # the provider genuinely exists exactly once afterwards.
    fetched = control.get_api_key_credential_provider(name=name)
    assert fetched["name"] == name, f"expected name={name!r}, got {fetched.get('name')!r}"


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
