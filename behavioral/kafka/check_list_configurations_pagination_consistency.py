"""list-configurations-pagination-consistency."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "list-configurations-pagination-consistency"
GROUP = 'configuration'
SERVICES = ['kafka']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConfigurations drained one item per page (MaxResults=1) returns each of three created
    configuration ARNs exactly once."""
    msk = ctx.client("kafka")
    created_arns = []
    for i in range(3):
        name = ctx.unique_name(f"sim2real-behav-page-config-{i}-")
        resp = msk.create_configuration(
            Name=name,
            ServerProperties=b"auto.create.topics.enable=true\n",
            KafkaVersions=["3.6.0"],
        )
        arn = resp["Arn"]
        created_arns.append(arn)
        ctx.on_cleanup(lambda _a=arn: msk.delete_configuration(Arn=_a))

    seen_arns = []
    next_token = None
    for _ in range(200):
        kwargs = {"MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = msk.list_configurations(**kwargs)
        seen_arns.extend(c["Arn"] for c in page.get("Configurations", []))
        next_token = page.get("NextToken")
        if not next_token:
            break

    for arn in created_arns:
        actual = seen_arns.count(arn)
        assert actual == 1, (
            f"expected {arn} exactly once across drained ListConfigurations pages, "
            f"saw it {actual} times (total items seen: {len(seen_arns)})"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
