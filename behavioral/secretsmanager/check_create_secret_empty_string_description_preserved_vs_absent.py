"""create-secret-empty-string-description-preserved-vs-absent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-secret-empty-string-description-preserved-vs-absent"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An empty-string Description is normalized away like an absent one: neither surfaces a
    Description key on DescribeSecret, while a non-empty Description does (positive control)."""
    sm = ctx.client("secretsmanager")

    name_empty = ctx.unique_name("sim2real-behav-descempty-")
    name_absent = ctx.unique_name("sim2real-behav-descabsent-")
    name_set = ctx.unique_name("sim2real-behav-descset-")

    owner_tag = [{"Key": "sim2real-owner", "Value": "behavioral-check"}]

    sm.create_secret(Name=name_empty, SecretString="v", Description="", Tags=owner_tag)
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name_empty, ForceDeleteWithoutRecovery=True))

    sm.create_secret(Name=name_absent, SecretString="v", Tags=owner_tag)
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name_absent, ForceDeleteWithoutRecovery=True))

    sm.create_secret(Name=name_set, SecretString="v", Description="a real description", Tags=owner_tag)
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name_set, ForceDeleteWithoutRecovery=True))

    desc_empty = sm.describe_secret(SecretId=name_empty)
    desc_absent = sm.describe_secret(SecretId=name_absent)
    desc_set = sm.describe_secret(SecretId=name_set)

    # Positive control FIRST: DescribeSecret does surface a Description when one was stored, so the
    # two absence assertions below are discriminating rather than vacuous.
    assert desc_set.get("Description") == "a real description", (
        "expected DescribeSecret to echo a stored non-empty Description, got "
        f"{desc_set.get('Description')!r} -- without this the absence assertions prove nothing"
    )

    # Empirically, Secrets Manager treats an explicit empty-string Description the same as an
    # absent one: it does not store/echo an empty Description key on DescribeSecret. Both must
    # behave identically -- no Description key surfaces in either case.
    assert "Description" not in desc_empty, (
        "explicit empty-string Description unexpectedly surfaced as a key in DescribeSecret "
        f"(got {desc_empty.get('Description')!r})"
    )
    assert "Description" not in desc_absent, "absent Description surfaced as a key in DescribeSecret"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
