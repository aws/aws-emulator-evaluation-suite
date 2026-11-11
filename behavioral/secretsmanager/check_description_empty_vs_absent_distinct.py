"""description-empty-vs-absent-distinct."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "description-empty-vs-absent-distinct"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Description='' and an omitted Description are indistinguishable: Secrets Manager normalizes
    the empty string to absent, so DescribeSecret returns no Description field in either case."""
    sm = ctx.client("secretsmanager")
    name_empty = ctx.unique_name("sim2real-behav-desc-empty-")
    name_absent = ctx.unique_name("sim2real-behav-desc-absent-")

    sm.create_secret(
        Name=name_empty,
        SecretString="v",
        Description="",
        Tags=[{"Key": "env", "Value": "test"}],
    )
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=name_empty, ForceDeleteWithoutRecovery=True)
    )

    sm.create_secret(
        Name=name_absent,
        SecretString="v",
        Tags=[{"Key": "env", "Value": "test"}],
    )
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=name_absent, ForceDeleteWithoutRecovery=True)
    )

    desc_empty = sm.describe_secret(SecretId=name_empty)
    desc_absent = sm.describe_secret(SecretId=name_absent)

    assert desc_empty.get("Description") in (None, ""), (
        f"expected empty Description to normalize to absent/empty, got "
        f"{desc_empty.get('Description')!r}"
    )
    assert "Description" not in desc_absent, (
        f"omitted Description unexpectedly present: {desc_absent.get('Description')!r}"
    )
    assert desc_empty.get("Description") == desc_absent.get("Description"), (
        "expected Description='' and omitted Description to be indistinguishable on "
        f"read-back, got {desc_empty.get('Description')!r} vs "
        f"{desc_absent.get('Description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
