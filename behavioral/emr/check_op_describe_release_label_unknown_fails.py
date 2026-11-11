"""op-describe-release-label-unknown-fails."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

CHECK = "op-describe-release-label-unknown-fails"
GROUP = 'overly-permissive'
SERVICES = ['emr']

@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: DescribeReleaseLabel for a nonexistent release label
    must fail, not return an empty success."""
    emr = ctx.client("emr")

    labels = emr.list_release_labels().get("ReleaseLabels", [])
    assert labels, "ListReleaseLabels returned no release labels; cannot run positive control"
    good_label = labels[0]
    desc = emr.describe_release_label(ReleaseLabel=good_label)
    assert desc.get("ReleaseLabel") == good_label, (
        f"positive control failed: describing a real release label {good_label!r} "
        f"did not echo it back, got {desc.get('ReleaseLabel')!r}"
    )

    code, message = _error(
        lambda: emr.describe_release_label(ReleaseLabel="emr-0.0.0-does-not-exist")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "The release label isn't valid.", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
