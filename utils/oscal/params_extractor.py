#!/usr/bin/env python3

"""Extract parameters from var files."""

import logging
import os
from typing import Any, Dict, Generator

import ssg.build_yaml
from ssg.utils import required_key

from utils.oscal import get_benchmark_root

logger = logging.getLogger(__name__)

VAR_FILE_EXTENSION = ".var"


def find_var_files(directory: str) -> Generator[str, None, None]:
    """Yield all files in a directory with a given extension."""
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(VAR_FILE_EXTENSION):
                yield os.path.join(root, file)


class ParamInfo:
    """Stores parameter information."""

    def __init__(self, param_id: str, description: str) -> None:
        """Initialize."""
        self._id = param_id
        self._description = description
        self._value = ""
        self._options: Dict[str, str] = dict()

    @property
    def id(self) -> str:
        """Get the id."""
        return self._id

    @property
    def description(self) -> str:
        """Get the description."""
        return self._description

    @property
    def default_value(self) -> str:
        """Get the default value."""
        return self._value

    @property
    def options(self) -> Dict[str, str]:
        """Get the options."""
        return self._options

    def set_default_value(self, value: str) -> None:
        """Set the default value."""
        self._value = value

    def set_options(self, value: Dict[str, str]) -> None:
        """Set the options."""
        self._options = value


class ParameterExtractor:
    """To extract parameters from var files"""

    def __init__(self, root: str, env_yaml: Dict[str, Any]) -> None:
        """Initialize."""
        self.root = root
        self.env_yaml = env_yaml
        self.product = required_key(env_yaml, "product")
        self._params_by_id: Dict[str, ParamInfo] = dict()

        benchmark_root = get_benchmark_root(root, self.product)
        for file in find_var_files(benchmark_root):
            try:
                value_yaml = ssg.build_yaml.Value.from_yaml(file, env_yaml)
                parameter_id = os.path.basename(file).replace(VAR_FILE_EXTENSION, "")
                default = required_key(value_yaml.options, "default")
                param_obj = ParamInfo(
                    parameter_id,
                    value_yaml.description.replace("\n", " ").strip(),
                )
                param_obj.set_default_value(default)
                param_obj.set_options(value_yaml.options)
                logger.debug(f"Adding parameter {parameter_id}")
                self._params_by_id[parameter_id] = param_obj
            except ValueError as e:
                logger.warning(f"Invalid var file {file}: {e}")

    def get_params_for_id(self, param_id: str) -> ParamInfo:
        """Get the parameter information for a parameter id."""
        if param_id not in self._params_by_id:
            raise ValueError(f"Could not find parameter {param_id}")
        return self._params_by_id[param_id]
