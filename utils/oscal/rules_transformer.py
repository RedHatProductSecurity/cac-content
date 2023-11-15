#!/usr/bin/env python3

"""Transform rules from existing Compliance as Code locations into OSCAL properties."""

import json
import logging
import re
from html.parser import HTMLParser
from typing import Any, List, Dict, Tuple, Optional

from trestle.oscal.common import Property
from trestle.tasks.csv_to_oscal_cd import (
    PARAMETER_DESCRIPTION,
    PARAMETER_ID,
    PARAMETER_VALUE_ALTERNATIVES,
    PARAMETER_VALUE_DEFAULT,
    # TODO(jpower432): Make this public in trestle
    # https://github.com/IBM/compliance-trestle/issues/1475
    _RuleSetIdMgr,
    RULE_DESCRIPTION,
    RULE_ID,
)

import ssg.build_yaml
import ssg.products
import ssg.rules
from ssg.utils import required_key

from utils.oscal import get_benchmark_root, add_prop
from utils.oscal.params_extractor import ParameterExtractor, ParamInfo

logger = logging.getLogger(__name__)


XCCDF_VARIABLE = "xccdf_variable"


class HTMLFilter(HTMLParser):
    """Strip HTML tags from a string."""

    def __init__(self) -> None:
        super().__init__()
        self.text: str = ""

    def handle_data(self, data: str) -> None:
        """Handle data by adding it to the saved text."""
        self.text += data


class RuleInfo:
    """Stores rule information."""

    def __init__(self, rule_id: str, rule_dir: str) -> None:
        """Initialize."""
        self._id = rule_id
        self._description = ""
        self._rule_dir = rule_dir
        self._parameters: List[ParamInfo] = list()

    @property
    def id(self) -> str:
        """Get the id."""
        return self._id

    @property
    def description(self) -> str:
        """Get the description."""
        return self._description

    @property
    def rule_dir(self) -> str:
        """Get the rule directory."""
        return self._rule_dir

    @property
    def parameters(self) -> List[ParamInfo]:
        """Get the parameters."""
        return self._parameters

    def add_description(self, value: str) -> None:
        """Add a check-export."""
        self._description = value

    def add_parameter(self, value: ParamInfo) -> None:
        """Add a fix."""
        self._parameters.append(value)


class RulesTransformer:
    """Transforms rules into properties for creating component definitions."""

    def __init__(
        self,
        root: str,
        env_yaml: Dict[str, Any],
        rule_dirs_json_path: str,
        param_extractor: ParameterExtractor,
    ) -> None:
        """Initialize."""
        with open(rule_dirs_json_path, "r") as f:
            rule_dir_json = json.load(f)
        self.rule_json = rule_dir_json
        self.root = root
        self.env_yaml = env_yaml
        self.product = required_key(env_yaml, "product")
        self.param_extractor = param_extractor

        benchmark_root = get_benchmark_root(root, self.product)
        self.rules_dirs_for_product: Dict[str, str] = dict()
        for dir_path in ssg.rules.find_rule_dirs_in_paths([benchmark_root]):
            rule_id = ssg.rules.get_rule_dir_id(dir_path)
            self.rules_dirs_for_product[rule_id] = dir_path

    def load(self, rules: List[str]) -> List[RuleInfo]:
        """Load a set of rules into rule objects based on ids."""
        rule_objs: List[RuleInfo] = list()
        rule_errors: List[str] = list()

        rules, params_values = self._process_rule_ids(rules)

        for rule_id in rules:
            try:
                rule_obj = self._new_rule_obj(rule_id)
                self._load_rule_yaml(rule_obj, params_values)
                rule_objs.append(rule_obj)
            except ValueError as e:
                rule_errors.append(f"Could not find rule {rule_id}: {e}")
            except FileNotFoundError as e:
                rule_errors.append(f"Could not load rule {rule_id}: {e}")

        if len(rule_errors) > 0:
            raise RuntimeError(
                f"Error loading rules: \
                    \n{', '.join(rule_errors)}"
            )
        return rule_objs

    def _process_rule_ids(
        self, rule_ids: List[str]
    ) -> Tuple[List[str], Dict[str, str]]:
        """
        Process rule ids.

        Notes: Rule ids with an "=" are parameters and should not be included when searching for
        rules.
        """
        processed_rule_ids: List[str] = list()
        params_values: Dict[str, str] = dict()
        for rule_id in rule_ids:
            parts = rule_id.split("=")
            if len(parts) == 2:
                param_id, value = parts
                params_values[param_id] = value
            else:
                processed_rule_ids.append(rule_id)
        return (processed_rule_ids, params_values)

    def _new_rule_obj(self, rule_id: str) -> RuleInfo:
        """Create a new rule object."""
        # Search the rules json first, then search the product benchmark
        # root directory if it does not exist.
        rule_dir = self._from_rules_json(rule_id)
        if not rule_dir:
            rule_dir = self._from_product_dir(rule_id)
        if not rule_dir:
            raise ValueError(
                f"Could not find rule {rule_id} in rules json or product directory."
            )
        rule_obj = RuleInfo(rule_id, rule_dir)
        return rule_obj

    def _from_rules_json(self, rule_id: str) -> Optional[str]:
        """Create rule object from rule yaml."""
        if rule_id not in self.rule_json:
            return None
        return self.rule_json[rule_id]["dir"]

    def _from_product_dir(self, rule_id: str) -> Optional[str]:
        """Locate the rule dir in the product directory."""
        if rule_id not in self.rules_dirs_for_product:
            return None
        return self.rules_dirs_for_product.get(rule_id)

    def _load_rule_yaml(
        self, rule_obj: RuleInfo, param_values: Optional[Dict[str, str]] = None
    ) -> None:
        """
        Update the rule object with the rule yaml data.

        Args:
            rule_obj: The rule object where collection rule data is stored.
            param_values: Parameter values from the ruleset.
        """
        rule_file = ssg.rules.get_rule_dir_yaml(rule_obj.rule_dir)
        rule_yaml = ssg.build_yaml.Rule.from_yaml(rule_file, env_yaml=self.env_yaml)
        rule_yaml.normalize(self.product)
        description = self._clean_rule_description(rule_yaml.description)
        rule_obj.add_description(description)
        self._get_params_ids(rule_yaml, rule_obj, param_values)

    @staticmethod
    def _clean_rule_description(description: str) -> str:
        """Clean the rule description."""
        filter = HTMLFilter()
        filter.feed(description)
        description = filter.text.replace("\n", " ").strip()
        cleaned_description = re.sub(' +', ' ', description)
        return cleaned_description

    def _get_params_ids(
        self,
        rule_yaml: ssg.build_yaml.Rule,
        rule_obj: RuleInfo,
        param_values: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Rules reference variables in a variety of ways.
        Each is attempted in order to find the parameter id.

        Args:
            rule_yaml: The rule yaml object.
            rule_obj: The rule object where collection rule data is stored.
            param_values: Parameter values from the ruleset.

        Notes:
            Just starting with the XCCDF variable for now for linking rules to parameters.
        """
        if not rule_yaml.is_templated():
            return

        xccdf_variable = rule_yaml.get_template_vars(self.env_yaml).get(XCCDF_VARIABLE)

        if xccdf_variable:
            param_id = xccdf_variable
            param = self.param_extractor.get_params_for_id(param_id=param_id)

            # Update the default value if provided by the ruleset under the control
            if param_values and param_id in param_values:
                param.set_default_value(param_values[param_id])

            rule_obj.add_parameter(param)
        else:
            logger.debug(f"Could not find {XCCDF_VARIABLE} for rule {rule_obj.id}")

    def _get_rule_properties(self, ruleset: str, rule_obj: RuleInfo) -> List[Property]:
        """Get a set of rule properties for a rule object."""
        rule_properties: List[Property] = list()
        rule_properties.append(add_prop(RULE_ID, rule_obj.id, ruleset))
        rule_properties.append(
            add_prop(RULE_DESCRIPTION, rule_obj.description, ruleset)
        )

        for param in rule_obj.parameters:
            rule_properties.extend(
                self._get_params_properties(ruleset, param)
            )

        return rule_properties

    @staticmethod
    def _get_params_properties(
        ruleset: str, param_info: ParamInfo
    ) -> List[Property]:
        """Get a set of parameter properties for a rule object."""
        id_prop = add_prop(PARAMETER_ID, param_info.id, ruleset)

        description_prop = add_prop(
            PARAMETER_DESCRIPTION, param_info.description, ruleset
        )
        default_prop = add_prop(
            PARAMETER_VALUE_DEFAULT,
            param_info.default_value,
            ruleset,
        )
        alternative_prop = add_prop(
            PARAMETER_VALUE_ALTERNATIVES,
            str(param_info.options),
            ruleset,
        )
        return [id_prop, description_prop, default_prop, alternative_prop]

    def transform(self, rule_objs: List[RuleInfo]) -> List[Property]:
        """Get the rules properties for a set of rule ids."""
        rule_properties: List[Property] = list()

        for i, rule_obj in enumerate(rule_objs):
            rule_set_mgr = _RuleSetIdMgr(i, len(rule_objs))
            rule_set_props = self._get_rule_properties(
                rule_set_mgr.get_next_rule_set_id(), rule_obj
            )
            rule_properties.extend(rule_set_props)
        return rule_properties
