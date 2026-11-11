"""document-get-resolves-default-not-latest."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "document-get-resolves-default-not-latest"
GROUP = 'state-machine'
SERVICES = ['ssm']


def _command_doc(marker):
    return json.dumps(
        {
            "schemaVersion": "2.2",
            "description": f"sim2real-behav document {marker}",
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": "echoMarker",
                    "inputs": {"runCommand": [f"echo {marker}"]},
                }
            ],
        }
    )


def _error(fn):
    """Return the ClientError error dict raised by fn; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll(probe, predicate, timeout_s=120, interval_s=3.0):
    """Poll until predicate holds: a document is Creating/Updating before Active, and
    GetDocument on a non-Active version can return stale content."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _marker(doc_content):
    """The echoed marker inside a returned document's content."""
    return json.loads(doc_content)["mainSteps"][0]["inputs"]["runCommand"][0].split()[-1]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UpdateDocument, an unpinned GetDocument still returns the DEFAULT (v1), not the latest;
    $LATEST, $DEFAULT, DescribeDocument and ListDocumentVersions agree before and after the switch.
    """

    ssm = ctx.client("ssm")

    name = ctx.unique_name("sim2real-behav-doc-")
    ssm.create_document(
        Name=name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Content=_command_doc("rev-one"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
    _poll(
        lambda: ssm.describe_document(Name=name)["Document"],
        lambda d: d.get("Status") == "Active",
    )

    v1 = ssm.get_document(Name=name)
    assert v1["DocumentVersion"] == "1", v1
    assert _marker(v1["Content"]) == "rev-one", v1["Content"]

    updated = ssm.update_document(
        Name=name, Content=_command_doc("rev-two"), DocumentVersion="$LATEST"
    )
    assert updated["DocumentDescription"]["DocumentVersion"] == "2", updated
    _poll(
        lambda: ssm.describe_document(Name=name, DocumentVersion="2")["Document"],
        lambda d: d.get("Status") == "Active",
    )

    # --- the discriminating state: latest is 2, default is still 1 -----------
    unpinned = ssm.get_document(Name=name)
    assert unpinned["DocumentVersion"] == "1", (
        "an unpinned GetDocument must resolve the DEFAULT version, which is still 1 after "
        f"UpdateDocument; got {unpinned['DocumentVersion']!r}"
    )
    assert _marker(unpinned["Content"]) == "rev-one", (
        "an unpinned GetDocument must return the default version's CONTENT, not the "
        f"latest content; got marker {_marker(unpinned['Content'])!r}"
    )

    latest = ssm.get_document(Name=name, DocumentVersion="$LATEST")
    assert latest["DocumentVersion"] == "2", latest
    assert _marker(latest["Content"]) == "rev-two", latest["Content"]

    default = ssm.get_document(Name=name, DocumentVersion="$DEFAULT")
    assert default["DocumentVersion"] == "1", default
    assert _marker(default["Content"]) == "rev-one", default["Content"]
    assert default["Content"] == unpinned["Content"], (
        "$DEFAULT and an unpinned read must be byte-identical"
    )
    assert latest["Content"] != default["Content"], (
        "$LATEST and $DEFAULT must differ while the default lags behind the latest"
    )

    described = ssm.describe_document(Name=name)["Document"]
    assert described["DocumentVersion"] == "1", (
        "DescribeDocument without a version must describe the DEFAULT version, got "
        f"{described['DocumentVersion']!r}"
    )
    assert described["LatestVersion"] == "2", described
    assert described["DefaultVersion"] == "1", described

    versions = {
        v["DocumentVersion"]: v
        for v in ssm.list_document_versions(Name=name)["DocumentVersions"]
    }
    assert set(versions) == {"1", "2"}, f"expected versions 1 and 2, got {sorted(versions)}"
    assert versions["1"]["IsDefaultVersion"] is True, versions["1"]
    assert versions["2"]["IsDefaultVersion"] is False, versions["2"]
    assert (
        sum(1 for v in versions.values() if v["IsDefaultVersion"]) == 1
    ), "exactly one version may be flagged IsDefaultVersion"

    # --- switch the default; every surface must flip together ---------------
    ssm.update_document_default_version(Name=name, DocumentVersion="2")

    flipped = _poll(
        lambda: ssm.describe_document(Name=name)["Document"],
        lambda d: d.get("DefaultVersion") == "2",
    )
    assert flipped["DocumentVersion"] == "2", flipped
    assert flipped["LatestVersion"] == "2", flipped

    after_unpinned = ssm.get_document(Name=name)
    assert after_unpinned["DocumentVersion"] == "2", after_unpinned
    assert _marker(after_unpinned["Content"]) == "rev-two", after_unpinned["Content"]
    after_default = ssm.get_document(Name=name, DocumentVersion="$DEFAULT")
    assert after_default["DocumentVersion"] == "2", after_default
    assert (
        after_default["Content"]
        == after_unpinned["Content"]
        == ssm.get_document(Name=name, DocumentVersion="$LATEST")["Content"]
    ), "with the default advanced to the latest, all three reads must agree"

    # Version 1 remains addressable by number — switching the default is not a delete.
    pinned_v1 = ssm.get_document(Name=name, DocumentVersion="1")
    assert pinned_v1["DocumentVersion"] == "1", pinned_v1
    assert _marker(pinned_v1["Content"]) == "rev-one", pinned_v1["Content"]

    after_versions = {
        v["DocumentVersion"]: v
        for v in ssm.list_document_versions(Name=name)["DocumentVersions"]
    }
    assert after_versions["2"]["IsDefaultVersion"] is True, after_versions["2"]
    assert after_versions["1"]["IsDefaultVersion"] is False, (
        "the old default must lose the flag; two versions may not both be default"
    )

    # --- negatives: unknown version, and a version that cannot be default ---
    unknown_version = _error(lambda: ssm.get_document(Name=name, DocumentVersion="99"))
    assert unknown_version["Code"] == "InvalidDocumentVersion", (
        f"GetDocument on a nonexistent version must be refused with InvalidDocumentVersion, "
        f"got {unknown_version!r}"
    )
    assert unknown_version["Message"] == (
        "Document version: 99 is invalid, latest version is 2"
    ), unknown_version["Message"]
    bad_default = _error(
        lambda: ssm.update_document_default_version(Name=name, DocumentVersion="99")
    )
    assert bad_default["Code"] == "InvalidDocumentVersion", (
        "UpdateDocumentDefaultVersion to a nonexistent version must be refused with "
        f"InvalidDocumentVersion, got {bad_default!r}"
    )
    assert bad_default["Message"] == (
        f"Document with name {name} with version 99 does not exist."
    ), bad_default["Message"]
    # Effect absent: the failed switch left the default where it was.
    assert ssm.describe_document(Name=name)["Document"]["DefaultVersion"] == "2", (
        "a refused default-version switch must not move the default"
    )
    unknown_name = "sim2real-behav-no-such-document"
    unknown_doc = _error(lambda: ssm.get_document(Name=unknown_name))
    assert unknown_doc["Code"] == "InvalidDocument", (
        f"GetDocument on an unknown name must be refused with InvalidDocument, got {unknown_doc!r}"
    )
    assert unknown_doc["Message"] == (
        f"Document with name {unknown_name} does not exist."
    ), unknown_doc["Message"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
