"""create-analyzer-duplicate-name-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-analyzer-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["accessanalyzer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """CreateAnalyzer rejects a name already in use with ConflictException and leaves the original
    untouched; deleting the original frees the name, and a differently named analyzer still creates."""
    aa = ctx.client("accessanalyzer")
    name = ctx.unique_name("sim2real-aa-dupe-")
    check_tags = {"sim2real": CHECK}
    arn = aa.create_analyzer(analyzerName=name, type="ACCOUNT", tags=check_tags)["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=name))

    code, message = _error(lambda: aa.create_analyzer(analyzerName=name, type="ACCOUNT"))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == "Analyzer with the same name already exists", message

    # effect absent: the original analyzer is unaffected by the rejected duplicate call
    analyzer = aa.get_analyzer(analyzerName=name)["analyzer"]
    assert analyzer["arn"] == arn, f"expected arn {arn}, got {analyzer['arn']}"
    assert analyzer["type"] == "ACCOUNT", f"expected type ACCOUNT, got {analyzer['type']}"

    # restore: the name conflict is a state (a live analyzer owns this name), not an
    # always-invalid input — freeing the name by deleting the original makes the
    # identical call that was just rejected succeed again.
    aa.delete_analyzer(analyzerName=name)
    restored_arn = aa.create_analyzer(analyzerName=name, type="ACCOUNT", tags=check_tags)["arn"]
    assert restored_arn == arn, f"expected identical arn {arn} on recreate, got {restored_arn}"
    restored = aa.get_analyzer(analyzerName=name)["analyzer"]
    assert restored["type"] == "ACCOUNT", f"expected type ACCOUNT after restore, got {restored['type']}"

    # positive control: analyzer creation isn't broken account-wide by the rejected
    # duplicate — a differently-named analyzer of a DIFFERENT type still creates fine.
    # (only one ACCOUNT-type analyzer is allowed per account+region, so the positive
    # control uses ACCOUNT_UNUSED_ACCESS to avoid tripping that unrelated quota.)
    other_name = ctx.unique_name("sim2real-aa-dupe-other-")
    other_arn = aa.create_analyzer(
        analyzerName=other_name, type="ACCOUNT_UNUSED_ACCESS", tags=check_tags
    )["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=other_name))
    assert other_arn != arn, f"expected an arn distinct from {arn}, got {other_arn}"

    # terminal read: independent of both create calls above
    other_analyzer = aa.get_analyzer(analyzerName=other_name)["analyzer"]
    assert other_analyzer["arn"] == other_arn, f"expected arn {other_arn}, got {other_analyzer['arn']}"
    assert other_analyzer["type"] == "ACCOUNT_UNUSED_ACCESS", (
        f"expected type ACCOUNT_UNUSED_ACCESS, got {other_analyzer['type']}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting what AWS refuses cannot be read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
