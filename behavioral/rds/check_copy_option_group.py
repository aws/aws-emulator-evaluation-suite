"""copy-option-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-option-group"
GROUP = 'option_groups'
SERVICES = ['rds']

ERR_OPTION_GROUP_NOT_FOUND = "OptionGroupNotFoundFault"


def _error_code(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _default_major_engine_version(ctx, engine: str) -> str:
    """MajorEngineVersion of the current default engine version for *engine*
    (e.g. "8.0"/"8.4" for mysql). Derived dynamically so the option group's
    MajorEngineVersion never drifts as AWS rotates the default away."""
    rds = ctx.client("rds")
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    return versions[0]["MajorEngineVersion"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyOptionGroup: copying a real option group produces an independently
    describable target group carrying the source's engine and major version. Error
    boundary: an unknown source group rejects with OptionGroupNotFoundFault.
    """
    rds = ctx.client("rds")
    major_version = _default_major_engine_version(ctx, "mysql")
    src_name = ctx.unique_name("sim2real-behav-og-src-")
    rds.create_option_group(
        OptionGroupName=src_name,
        EngineName="mysql",
        MajorEngineVersion=major_version,
        OptionGroupDescription="behavioral check source",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=src_name))

    bogus_src = ctx.unique_name("sim2real-behav-og-missing-")
    code, message = _error_code(
        lambda: rds.copy_option_group(
            SourceOptionGroupIdentifier=bogus_src,
            TargetOptionGroupIdentifier=ctx.unique_name("sim2real-behav-og-tgt-"),
            TargetOptionGroupDescription="should fail",
        )
    )
    assert code == ERR_OPTION_GROUP_NOT_FOUND, f"unexpected error code: {code}"
    assert message == f"Specified OptionGroupName: {bogus_src} not found.", message

    tgt_name = ctx.unique_name("sim2real-behav-og-tgt-")
    rds.copy_option_group(
        SourceOptionGroupIdentifier=src_name,
        TargetOptionGroupIdentifier=tgt_name,
        TargetOptionGroupDescription="behavioral check target",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=tgt_name))
    resp = rds.describe_option_groups(OptionGroupName=tgt_name)
    groups = resp["OptionGroupsList"]
    assert [g["OptionGroupName"] for g in groups] == [tgt_name], (
        f"expected exactly the copied group {tgt_name!r}, describe returned {groups!r}"
    )
    copied = groups[0]
    got = (copied.get("EngineName"), copied.get("MajorEngineVersion"), copied.get("OptionGroupDescription"))
    want = ("mysql", major_version, "behavioral check target")
    assert got == want, (
        f"copied group (EngineName, MajorEngineVersion, OptionGroupDescription) {got!r}, "
        f"expected the source's engine/version and the target description {want!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
