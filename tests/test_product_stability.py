from __future__ import print_function

import argparse
import glob
import os.path
import sys

import ssg.products


class Difference(object):
    def __init__(self):
        self.added = []
        self.removed = []
        self.modified = dict()

    @property
    def empty(self):
        return not (self.added or self.removed or self.modified)


def describe_changeset(intro, changeset):
    if not changeset:
        return ""

    msg = intro
    for rid in changeset:
        msg += " - {rid}\n".format(rid=rid)
    return msg


def describe_modification(intro, changeset):
    if not changeset:
        return ""

    msg = intro
    for what, (initial, final) in changeset.items():
        msg += " - {what} from '{initial}' -> '{final}'\n".format(
                what=what, initial=initial, final=final)
    return msg


def describe_change(difference, name):
    msg = ""

    msg += describe_changeset(
        "Following properties were added to the {name} product:\n".format(name=name),
        difference.added,
    )
    msg += describe_changeset(
        "Following properties were removed from the {name} product:\n".format(name=name),
        difference.removed,
    )
    msg += describe_modification(
        "Following properties got different values in the {name} product:\n".format(name=name),
        difference.modified,
    )
    return msg.rstrip()


def compare_dictionaries(reference, sample):
    reference_keys = set(reference.keys())
    sample_keys = set(sample.keys())

    result = Difference()
    result.added = list(sample_keys.difference(reference_keys))
    result.removed = list(reference_keys.difference(sample_keys))
    for key, value in reference.items():
        if sample.get(key, value) != value:
            result.modified[key] = (value, sample[key])
    return result


def report_comparison(name, result):
    msg = ""
    if not result.empty:
        msg = describe_change(result, name)
    print(msg, file=sys.stderr)


def get_references(ref_root):
    return glob.glob(os.path.join(ref_root, "*.yml"))


def corresponding_product_built(build_dir, product_id):
    return os.path.isdir(os.path.join(build_dir, product_id))


def get_matching_compiled_product_filename(build_dir, product_id):
    ref_path_components = reference_fname.split(os.path.sep)
    matching_filename = os.path.join(build_dir, product_id, "product.yml")
    if os.path.isfile(matching_filename):
        return matching_filename


def get_reference_vs_built_difference(ref_product, built_product):
    ref_dict = dict()
    ref_dict.update(ref_product)
    built_dict = dict()
    built_dict.update(built_product)
    difference = compare_dictionaries(ref_dict, built_dict)
    return difference


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build_root")
    parser.add_argument("test_data_root")
    args = parser.parse_args()

    reference_files = get_references(args.test_data_root)
    if not reference_files:
        raise RuntimeError("Unable to find any reference compiled products in {test_root}"
                           .format(test_root=args.test_data_root))
    fix_commands = []
    for ref in reference_files:
        ref_product = ssg.products.Product(ref)
        product_id = ref_product["product"]
        if not corresponding_product_built(args.build_root, product_id):
            continue

        compiled_path = os.path.join(args.build_root, product_id, "product.yml")
        compiled_product = ssg.products.Product(compiled_path)
        if not compiled_product:
            msg = ("Unexpectedly unable to find compiled product file corresponding"
                   "to the test file {ref}, although the corresponding product has been built. "
                   "This indicates that a profile we have tests for is missing."
                   .format(ref=ref))
            raise RuntimeError(msg)
        difference = get_reference_vs_built_difference(ref_product, compiled_product)
        if not difference.empty:
            report_comparison(product_id, difference)
            fix_commands.append(
                "cp '{compiled}' '{reference}'"
                .format(compiled=compiled_path, reference=ref)
            )

    if fix_commands:
        msg = (
            "If changes to mentioned products are intentional, "
            "copy those compiled files, so they become the new reference:\n{fixes}\n"
            "If those changes are unwanted, take a look at product properties "
            "that likely cause these changes."
            .format(fixes="\n".join(fix_commands)))
        print(msg, file=sys.stderr)
    sys.exit(bool(fix_commands))


if __name__ == "__main__":
    main()

