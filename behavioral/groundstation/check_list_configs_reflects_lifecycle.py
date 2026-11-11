"""list-configs-reflects-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-configs-reflects-lifecycle"
GROUP = "state"
SERVICES = ["groundstation"]


def _list_all_config_ids(gs) -> set:
    ids = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = gs.list_configs(**kwargs)
        for entry in page.get("configList", []):
            ids.add(entry["configId"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    return ids


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConfigs includes a newly created Config and stops including it after deletion."""
    gs = ctx.client("groundstation")
    keep = gs.create_config(
        name=ctx.unique_name("sim2real-gs-keep-"),
        configData={"trackingConfig": {"autotrack": "REMOVED"}},
        tags={"sim2real:managed": "true"},
    )
    keep_id, keep_type = keep["configId"], keep["configType"]
    ctx.on_cleanup(lambda: gs.delete_config(configId=keep_id, configType=keep_type))

    doomed = gs.create_config(
        name=ctx.unique_name("sim2real-gs-doomed-"),
        configData={"trackingConfig": {"autotrack": "PREFERRED"}},
        tags={"sim2real:managed": "true"},
    )
    doomed_id, doomed_type = doomed["configId"], doomed["configType"]

    ids_before = _list_all_config_ids(gs)
    assert keep_id in ids_before, f"expected keep config {keep_id} in ListConfigs, got {ids_before}"
    assert doomed_id in ids_before, (
        f"expected doomed config {doomed_id} in ListConfigs, got {ids_before}"
    )

    gs.delete_config(configId=doomed_id, configType=doomed_type)

    ids_after = _list_all_config_ids(gs)
    assert keep_id in ids_after, f"expected keep config {keep_id} to remain listed, got {ids_after}"
    assert doomed_id not in ids_after, (
        f"expected deleted config {doomed_id} to be excluded from ListConfigs, got {ids_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
