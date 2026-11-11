"""classifier-create-get-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "classifier-create-get-delete"
GROUP = 'classifier'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create_classifier (Grok) -> get_classifier reflects the pattern -> delete_classifier removes it."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-classifier-")
    pattern = "%{NOTSPACE:col1} %{NOTSPACE:col2}"

    glue.create_classifier(
        GrokClassifier={
            "Classification": "custom",
            "Name": name,
            "GrokPattern": pattern,
        }
    )
    ctx.on_cleanup(lambda: _delete_classifier_ignore_missing(glue, name))

    resp = glue.get_classifier(Name=name)
    grok = resp["Classifier"]["GrokClassifier"]
    assert grok["Name"] == name, f"expected classifier name {name!r}, got {grok.get('Name')!r}"
    assert grok["GrokPattern"] == pattern, (
        f"expected GrokPattern {pattern!r}, got {grok.get('GrokPattern')!r}"
    )

    glue.delete_classifier(Name=name)

    try:
        result = glue.get_classifier(Name=name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"GetClassifier on a deleted classifier succeeded: {result!r}")
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    assert message == f"Classifier {name} not found. not found.", message


def _delete_classifier_ignore_missing(glue, name: str) -> None:
    """Teardown: the check deletes the classifier itself, so it is usually gone already."""
    try:
        glue.delete_classifier(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
