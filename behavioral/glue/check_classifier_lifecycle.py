"""classifier-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "classifier-lifecycle"
GROUP = 'classifier'
SERVICES = ['glue']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CsvClassifier create -> get -> update (delimiter) -> delete."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-glue-clsf-")
    glue.create_classifier(
        CsvClassifier={
            "Name": name,
            "Delimiter": ",",
            "QuoteSymbol": '"',
            "ContainsHeader": "PRESENT",
            "Header": ["id", "amount"],
        }
    )
    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_classifier(Name=name)))

    clsf = glue.get_classifier(Name=name)["Classifier"]["CsvClassifier"]
    assert clsf["Delimiter"] == ",", f"unexpected delimiter: {clsf}"
    assert clsf["ContainsHeader"] == "PRESENT", f"unexpected ContainsHeader: {clsf}"

    glue.update_classifier(CsvClassifier={"Name": name, "Delimiter": "|"})
    updated = glue.get_classifier(Name=name)["Classifier"]["CsvClassifier"]
    assert updated["Delimiter"] == "|", f"UpdateClassifier did not persist delimiter: {updated}"

    names = [
        c["CsvClassifier"]["Name"]
        for c in glue.get_classifiers()["Classifiers"]
        if "CsvClassifier" in c
    ]
    assert name in names, "classifier missing from GetClassifiers listing"

    glue.delete_classifier(Name=name)
    code, message = _error(lambda: glue.get_classifier(Name=name))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after DeleteClassifier, got {code!r}"
    )
    assert message == f"Classifier {name} not found. not found.", message

    update_code, update_message = _error(
        lambda: glue.update_classifier(CsvClassifier={"Name": name, "Delimiter": ";"})
    )
    assert update_code == "EntityNotFoundException", (
        f"expected UpdateClassifier on deleted classifier to fail with "
        f"EntityNotFoundException, got {update_code!r}"
    )
    assert update_message == f"Classifier {name} not found. not found.", update_message


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


def _quiet(fn):
    """Best-effort teardown call — the resource may already be gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
