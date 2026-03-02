import importlib


def test_persistence_module_importable_cross_platform():
    module = importlib.import_module("detection.persistence_monitor")
    assert hasattr(module, "start_persistence_monitor")
