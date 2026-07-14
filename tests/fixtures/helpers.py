"""Test helper functions."""
import importlib.util
import pathlib
import sys
from typing import Any, Dict, Optional


def load_module_with_stubs(
    module_path: pathlib.Path,
    module_name: str,
    stubs: Optional[Dict[str, Any]] = None
):
    """Load a module from path with optional stub modules injected."""
    if stubs:
        for name, obj in stubs.items():
            sys.modules[name] = obj

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    return module
