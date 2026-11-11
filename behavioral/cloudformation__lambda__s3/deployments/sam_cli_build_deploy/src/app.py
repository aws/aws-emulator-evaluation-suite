import os


def handler(event, context):
    here = os.path.dirname(os.path.abspath(__file__))
    return {"here": here, "files": sorted(os.listdir(here))}
