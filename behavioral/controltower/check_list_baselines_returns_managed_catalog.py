"""list-baselines-returns-managed-catalog."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-baselines-returns-managed-catalog"
GROUP = "catalog"
SERVICES = ["controltower"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBaselines returns the fixed AWS-managed baseline catalog (not a per-account
    resource), and the well-known AWSControlTowerBaseline entry is always present with
    a well-formed ARN, since it is the baseline used to register organizational units."""
    ct = ctx.client("controltower")
    resp = ct.list_baselines(maxResults=100)
    baselines = resp["baselines"]
    assert len(baselines) > 0, "expected at least one AWS-managed baseline in the catalog"

    names = {b["name"] for b in baselines}
    assert "AWSControlTowerBaseline" in names, f"expected AWSControlTowerBaseline in catalog, got {names}"

    caller_account = ctx.client("sts").get_caller_identity()["Account"]
    for b in baselines:
        assert b["arn"].startswith("arn:aws"), f"malformed baseline arn: {b['arn']}"
        assert ":controltower:" in b["arn"], f"baseline arn missing controltower namespace: {b['arn']}"
        assert b["arn"].split("/")[-1], "baseline arn missing resource id suffix"
        assert caller_account not in b["arn"], (
            f"baseline arn embeds the caller's own account {caller_account}, "
            f"but the catalog is AWS-managed, not per-account: {b['arn']}"
        )

    # names should be unique across the catalog
    assert len(names) == len(baselines), "duplicate baseline names in catalog"

    # a second, independent read must return the identical catalog: nothing here is
    # per-account state that could drift between two reads in the same run
    again = {b["arn"] for b in ct.list_baselines(maxResults=100)["baselines"]}
    assert again == {b["arn"] for b in baselines}, (
        f"catalog changed between two reads in the same run: {again} vs "
        f"{ {b['arn'] for b in baselines} }"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
