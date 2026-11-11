"""athena-workgroup-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-workgroup-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWorkGroup with a Name that already exists is rejected; the original is left untouched."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-wg-")

    athena.create_work_group(
        Name=name, Description="original", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    from botocore.exceptions import ClientError

    try:
        athena.create_work_group(Name=name, Description="duplicate-attempt")
        raise AssertionError("expected duplicate CreateWorkGroup to raise InvalidRequestException")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "InvalidRequestException", exc.response["Error"]
        assert exc.response["Error"]["Message"] == "WorkGroup is already created", exc.response["Error"]

    # The forbidden effect (overwriting Description) did not happen.
    wg = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert wg["Description"] == "original"

    # Positive control: a genuinely unique name succeeds.
    other_name = name + "-other"
    athena.create_work_group(Name=other_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=other_name, RecursiveDeleteOption=True))
    assert athena.get_work_group(WorkGroup=other_name)["WorkGroup"]["State"] == "ENABLED"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
