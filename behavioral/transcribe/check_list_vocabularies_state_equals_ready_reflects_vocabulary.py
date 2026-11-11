"""list-vocabularies-state-equals-ready-reflects-vocabulary."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-vocabularies-state-equals-ready-reflects-vocabulary"
GROUP = "read"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVocabularies(StateEquals="READY") reflects a vocabulary that has actually
    finished processing, exercising the state filter (distinct from the name filter)."""
    tx = ctx.client("transcribe")
    name = ctx.unique_name("sim2real-behav-vocab-statefilter-")
    create_resp = tx.create_vocabulary(
        VocabularyName=name,
        LanguageCode="en-US",
        Phrases=["Heavy", "Falcon"],
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_vocabulary_ignore_missing(ctx, name))

    assert create_resp["VocabularyState"] == "PENDING", (
        f"expected PENDING immediately after create, got {create_resp['VocabularyState']}"
    )
    still_pending = _list_ready_names(ctx)
    assert name not in still_pending, (
        f"{name} appeared in ListVocabularies(StateEquals=READY) while still PENDING: {still_pending}"
    )

    final_state = _poll_vocabulary_state(ctx, name, timeout_s=300, interval_s=10)
    assert final_state == "READY"

    found = _list_ready_names(ctx)
    assert name in found, f"{name} missing from ListVocabularies(StateEquals=READY)"


def _list_ready_names(ctx) -> set[str]:
    tx = ctx.client("transcribe")
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"StateEquals": "READY", "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = tx.list_vocabularies(**kwargs)
        for v in resp.get("Vocabularies", []):
            names.add(v["VocabularyName"])
        token = resp.get("NextToken")
        if not token:
            return names


def _poll_vocabulary_state(ctx, name: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    tx = ctx.client("transcribe")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = tx.get_vocabulary(VocabularyName=name)["VocabularyState"]
        if state != "PENDING":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"vocabulary {name} stayed PENDING for {timeout_s}s (last state={state})")


def _delete_vocabulary_ignore_missing(ctx, name: str) -> None:
    tx = ctx.client("transcribe")
    try:
        tx.delete_vocabulary(VocabularyName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "BadRequestException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
