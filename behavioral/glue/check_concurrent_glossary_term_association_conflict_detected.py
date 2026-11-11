"""concurrent-glossary-term-association-conflict-detected."""
from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-glossary-term-association-conflict-detected"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of 8 racing AssociateGlossaryTerms calls on one asset, at least one wins, losers get
    ConcurrentModificationException with message '{}', every winner's term is on the asset and no loser's term
    leaked; a fully serialized round passes too, as losing is not documented."""
    glue = ctx.client("glue")

    # The glossary first, so its teardown runs after the asset's and the terms' (LIFO).
    glossary_id = _create_glossary(ctx)
    form_type_id = _create_form_type(ctx)
    asset_type_id = _create_asset_type(ctx, form_type_id)
    asset_id = _create_asset(ctx, asset_type_id, form_type_id)

    racers = 8
    term_ids = [_create_glossary_term(ctx, glossary_id) for _ in range(racers)]

    def make_call(term_id: str):
        def _call():
            return glue.associate_glossary_terms(
                AssetIdentifier=asset_id, GlossaryTermIdentifiers=[term_id]
            )

        return _call

    outcomes = _race([make_call(t) for t in term_ids])

    successes = [o for o in outcomes if o["error"] is None]
    failures = [o for o in outcomes if o["error"] is not None]
    assert len(successes) >= 1, "no racer ever succeeded at associating a term"
    for failure in failures:
        assert failure["error"] == "ConcurrentModificationException", failure["error"]
        assert failure["message"] == "{}", failure["message"]

    succeeded_terms = {term_ids[i] for i, o in enumerate(outcomes) if o["error"] is None}
    failed_terms = {term_ids[i] for i, o in enumerate(outcomes) if o["error"] is not None}

    # effect, via an independent read: every racer the API told us won is actually on the
    # asset, and no racer the API rejected leaked its term onto it anyway.
    asset = glue.get_asset(Identifier=asset_id)
    current_terms = set(asset.get("GlossaryTerms", []))
    assert succeeded_terms <= current_terms, (
        f"succeeded terms {succeeded_terms} missing from final state {current_terms}"
    )
    assert not (failed_terms & current_terms), (
        f"a rejected association's term {failed_terms & current_terms} leaked into final state"
    )

    # positive control: the asset is not left in a broken state - a fresh, non-racing
    # association still succeeds normally afterwards, visible on an independent read.
    control_term = _create_glossary_term(ctx, glossary_id)
    glue.associate_glossary_terms(AssetIdentifier=asset_id, GlossaryTermIdentifiers=[control_term])
    after = glue.get_asset(Identifier=asset_id)
    assert control_term in set(after.get("GlossaryTerms", [])), (
        f"control term {control_term} not present after independent read of {after.get('GlossaryTerms')}"
    )


def _sanitize(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", s)


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_form_type(ctx) -> str:
    glue = ctx.client("glue")
    name = "SimForm" + _sanitize(ctx.unique_name("x"))[-12:]
    glue.put_form_type(Name=name, Schema=f"structure {name} {{\n    note: String\n}}")
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_form_type(Identifier=name)))
    return name


def _create_asset_type(ctx, form_type_id: str) -> str:
    glue = ctx.client("glue")
    name = "SimType" + _sanitize(ctx.unique_name("x"))[-12:]
    glue.put_asset_type(Name=name, Forms={"Note": {"FormTypeIdentifier": form_type_id}})
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_asset_type(Identifier=name)))
    return name


def _create_asset(ctx, asset_type_id: str, form_type_id: str) -> str:
    glue = ctx.client("glue")
    identifier = ctx.unique_name("sim2real-asset-")
    glue.put_asset(
        AssetTypeId=asset_type_id,
        Identifier=identifier,
        Name=identifier,
        Forms={"Note": {"FormTypeId": form_type_id, "Content": json.dumps({"note": "init"})}},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_asset(Identifier=identifier)))
    return identifier


def _create_glossary(ctx) -> str:
    glue = ctx.client("glue")
    resp = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))
    glossary_id = resp["Id"]
    ctx.on_cleanup(lambda: _delete_glossary(glue, glossary_id))
    return glossary_id


_GLOSSARY_TEARDOWN_S = 120.0


def _delete_glossary(glue, glossary_id: str) -> None:
    """Delete the glossary. DeleteGlossary answers ConflictException while deleted terms still
    count as its dependencies, so that answer is retried every 2 s within one deadline."""
    deadline = time.monotonic() + _GLOSSARY_TEARDOWN_S
    while True:
        try:
            glue.delete_glossary(Identifier=glossary_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_glossary_term(ctx, glossary_id: str) -> str:
    glue = ctx.client("glue")
    resp = glue.create_glossary_term(GlossaryIdentifier=glossary_id, Name=ctx.unique_name("term-"))
    term_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_glossary_term(Identifier=term_id)))
    return term_id


def _race(calls: list) -> list:
    """Fire all zero-arg callables at as close to the same instant as possible via a barrier;
    return a list of {"result": ..., "error": <code or None>, "message": <message or None>} dicts,
    one per call, in call order."""
    n = len(calls)
    barrier = threading.Barrier(n)
    outcomes: list = [None] * n

    def worker(i: int, fn) -> None:
        barrier.wait()
        try:
            outcomes[i] = {"result": fn(), "error": None, "message": None}
        except ClientError as e:
            error = e.response["Error"]
            outcomes[i] = {"result": None, "error": error["Code"], "message": error.get("Message")}

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(worker, i, fn) for i, fn in enumerate(calls)]
        for f in futures:
            f.result()
    return outcomes


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
