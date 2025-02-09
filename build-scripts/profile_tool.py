#!/usr/bin/python3

from __future__ import print_function

import json
import argparse
import jinja2
import os
import os.path

try:
    import ssg.build_profile
    import ssg.constants
    import ssg.environment
    import ssg.xml
    import ssg.build_yaml
    from ssg.utils import mkdir_p
except ImportError:
    print("The ssg module could not be found.")
    print("Run .pyenv.sh available in the project root diretory,"
          " or add it to PYTHONPATH manually.")
    print("$ source .pyenv.sh")
    exit(1)


def parse_args():
    script_desc = \
        "Obtains and displays XCCDF profile statistics. Namely number " + \
        "of rules in the profile, how many of these rules have their OVAL " + \
        "check implemented, how many have a remediation available, ..."

    parser = argparse.ArgumentParser(description="Profile statistics and utilities tool")
    subparsers = parser.add_subparsers(title='subcommands', dest="subcommand")
    parser_stats = subparsers.add_parser("stats", description=script_desc,
                                           help=("Show profile statistics"))
    parser_stats.add_argument("--profile", "-p",
                        action="store",
                        help="Show statistics for this XCCDF Profile only. If "
                        "not provided the script will show stats for all "
                        "available profiles.")
    parser_stats.add_argument(
        "--benchmark", "-b", required=True, action="store",
        help="Specify XCCDF file or a SCAP source data stream file to act on.")
    parser_stats.add_argument("--implemented-ovals", default=False,
                        action="store_true", dest="implemented_ovals",
                        help="Show IDs of implemented OVAL checks.")
    parser_stats.add_argument("--implemented-sces", default=False,
                        action="store_true", dest="implemented_sces",
                        help="Show IDs of implemented SCE checks.")
    parser_stats.add_argument("--missing-stig-ids", default=False,
                        action="store_true", dest="missing_stig_ids",
                        help="Show rules in STIG profiles that don't have STIG IDs.")
    parser_stats.add_argument("--missing-cis-refs", default=False,
                        action="store_true", dest="missing_cis_refs",
                        help="Show rules in CIS profiles that don't have CIS references.")
    parser_stats.add_argument("--missing-hipaa-refs", default=False,
                        action="store_true", dest="missing_hipaa_refs",
                        help="Show rules in HIPAA profiles that don't have HIPAA references.")
    parser_stats.add_argument("--missing-anssi-refs", default=False,
                        action="store_true", dest="missing_anssi_refs",
                        help="Show rules in ANSSI profiles that don't have ANSSI references.")
    parser_stats.add_argument("--missing-ospp-refs", default=False,
                              action="store_true", dest="missing_ospp_refs",
                              help="Show rules in OSPP profiles that don't have OSPP references.")
    parser_stats.add_argument("--missing-cui-refs", default=False,
                              action="store_true", dest="missing_cui_refs",
                              help="Show rules in CUI profiles that don't have CUI references.")
    parser_stats.add_argument("--missing-ovals", default=False,
                        action="store_true", dest="missing_ovals",
                        help="Show IDs of unimplemented OVAL checks.")
    parser_stats.add_argument("--missing-sces", default=False,
                        action="store_true", dest="missing_sces",
                        help="Show IDs of unimplemented SCE checks.")
    parser_stats.add_argument("--implemented-fixes", default=False,
                        action="store_true", dest="implemented_fixes",
                        help="Show IDs of implemented remediations.")
    parser_stats.add_argument("--missing-fixes", default=False,
                        action="store_true", dest="missing_fixes",
                        help="Show IDs of unimplemented remediations.")
    parser_stats.add_argument("--assigned-cces", default=False,
                        action="store_true", dest="assigned_cces",
                        help="Show IDs of rules having CCE assigned.")
    parser_stats.add_argument("--missing-cces", default=False,
                        action="store_true", dest="missing_cces",
                        help="Show IDs of rules missing CCE element.")
    parser_stats.add_argument("--implemented", default=False,
                        action="store_true",
                        help="Equivalent of --implemented-ovals, "
                        "--implemented_fixes and --assigned-cves "
                        "all being set.")
    parser_stats.add_argument("--missing", default=False,
                        action="store_true",
                        help="Equivalent of --missing-ovals, --missing-fixes"
                        " and --missing-cces all being set.")
    parser_stats.add_argument("--ansible-parity",
                        action="store_true",
                        help="Show IDs of rules with Bash fix which miss Ansible fix."
                        " Rules missing both Bash and Ansible are not shown.")
    parser_stats.add_argument("--all", default=False,
                        action="store_true", dest="all",
                        help="Show all available statistics.")
    parser_stats.add_argument("--product", action="store", dest="product",
                              help="Product directory to evaluate XCCDF under "
                              "(e.g., ~/scap-security-guide/rhel8)")
    parser_stats.add_argument("--skip-stats", default=False,
                              action="store_true", dest="skip_overall_stats",
                              help="Do not show overall statistics.")
    parser_stats.add_argument("--format", default="plain",
                        choices=["plain", "json", "csv", "html"],
                        help="Which format to use for output.")
    parser_stats.add_argument("--output",
                        help="If defined, statistics will be stored under this directory.")

    subtracted_profile_desc = \
        "Subtract rules and variable selections from profile1 based on rules present in " + \
        "profile2. As a result, a new profile is generated. It doesn't support profile " + \
        "inheritance, this means that only rules explicitly " + \
        "listed in the profiles will be taken in account."

    parser_sub = subparsers.add_parser("sub", description=subtracted_profile_desc,
                                       help=("Subtract rules and variables from profile1 "
                                             "based on selections present in profile2."))
    parser_sub.add_argument(
        "--build-config-yaml", required=True,
        help="YAML file with information about the build configuration. "
        "e.g.: ~/scap-security-guide/build/build_config.yml "
        "needed for autodetection of profile root"
    )
    parser_sub.add_argument(
        "--ssg-root", required=True,
        help="Directory containing the source tree. "
        "e.g. ~/scap-security-guide/"
    )
    parser_sub.add_argument(
        "--product", required=True,
        help="ID of the product for which we are building Playbooks. "
        "e.g.: 'fedora'"
    )
    parser_sub.add_argument('--profile1', type=str, dest="profile1",
                        required=True, help='YAML profile')
    parser_sub.add_argument('--profile2', type=str, dest="profile2",
                        required=True, help='YAML profile')

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        exit(0)

    if args.subcommand == "stats":
        if args.all:
            args.implemented = True
            args.missing = True
            args.ansible_parity = True

        if args.implemented:
            args.implemented_ovals = True
            args.implemented_fixes = True
            args.assigned_cces = True

        if args.missing:
            args.missing_ovals = True
            args.missing_sces = True
            args.missing_fixes = True
            args.missing_cces = True
            args.missing_stig_ids = True
            args.missing_cis_refs = True
            args.missing_hipaa_refs = True
            args.missing_anssi_refs = True
            args.missing_ospp_refs = True
            args.missing_cui_refs = True

    return args


def main():
    args = parse_args()

    if args.subcommand == "sub":
        product_yaml = os.path.join(args.ssg_root, "products", args.product, "product.yml")
        env_yaml = ssg.environment.open_environment(args.build_config_yaml, product_yaml)
        try:
            profile1 = ssg.build_yaml.Profile.from_yaml(args.profile1, env_yaml)
            profile2 = ssg.build_yaml.Profile.from_yaml(args.profile2, env_yaml)
        except jinja2.exceptions.TemplateNotFound as e:
            print("Error: Profile {} could not be found.".format(str(e)))
            exit(1)

        subtracted_profile = profile1 - profile2

        exclusive_rules = len(subtracted_profile.get_rule_selectors())
        exclusive_vars = len(subtracted_profile.get_variable_selectors())
        if exclusive_rules > 0:
            print("{} rules were left after subtraction.".format(exclusive_rules))
        if  exclusive_vars > 0:
            print("{} variables were left after subtraction.".format(exclusive_vars))

        if exclusive_rules > 0 or exclusive_vars > 0:
            profile1_basename = os.path.splitext(
                os.path.basename(args.profile1))[0]
            profile2_basename = os.path.splitext(
                os.path.basename(args.profile2))[0]

            subtracted_profile_filename = "{}_sub_{}.profile".format(
                profile1_basename, profile2_basename)
            print("Creating a new profile containing the exclusive selections: {}".format(
                subtracted_profile_filename))

            subtracted_profile.title = profile1.title + " subtracted by " + profile2.title
            subtracted_profile.dump_yaml(subtracted_profile_filename)
            print("Profile {} was created successfully".format(
                subtracted_profile_filename))
        else:
            print("Subtraction would produce an empty profile. No new profile was generated")
        exit(0)

    benchmark = ssg.build_profile.XCCDFBenchmark(args.benchmark, args.product)
    ret = []
    if args.profile:
        ret.append(benchmark.show_profile_stats(args.profile, args))
    else:
        ret.extend(benchmark.show_all_profile_stats(args))

    if args.format == "json":
        print(json.dumps(ret, indent=4))
    if args.format == "html":
        from json2html import json2html
        filtered_output = []
        output_path = "./"
        if args.output:
            output_path = args.output
            mkdir_p(output_path)

        content_path = os.path.join(output_path, "content")
        mkdir_p(content_path)

        content_list = [
            'rules',
            'missing_stig_ids',
            'missing_cis_refs',
            'missing_hipaa_refs',
            'missing_anssi_refs',
            'missing_ospp_refs',
            'missing_cui_refs',
            'missing_ovals',
            'missing_sces',
            'missing_bash_fixes',
            'missing_ansible_fixes',
            'missing_ignition_fixes',
            'missing_kubernetes_fixes',
            'missing_puppet_fixes',
            'missing_anaconda_fixes',
            'missing_cces',
            'ansible_parity',
            'implemented_checks',
            'implemented_fixes',
            'missing_checks',
            'missing_fixes'
            ]
        link = """<a href="{}"><div style="height:100%;width:100%">{}</div></a>"""

        for profile in ret:
            bash_fixes_count = profile['rules_count'] - profile['missing_bash_fixes_count']
            for content in content_list:
                content_file = "{}_{}.txt".format(profile['profile_id'], content)
                content_filepath = os.path.join("content", content_file)
                count = len(profile[content])
                if count > 0:
                    if content == "ansible_parity":
                        #custom text link for ansible parity
                        count = link.format(content_filepath, "{} out of {} ({}%)".format(bash_fixes_count-count, bash_fixes_count, int(((bash_fixes_count-count)/bash_fixes_count)*100)))
                    count_href_element = link.format(content_filepath, count)
                    profile['{}_count'.format(content)] = count_href_element
                    with open(os.path.join(content_path, content_file), 'w+') as f:
                        f.write('\n'.join(profile[content]))
                else:
                    profile['{}_count'.format(content)] = count

                del profile[content]
            filtered_output.append(profile)

        with open(os.path.join(output_path, "statistics.html"), 'w+') as f:
            f.write(json2html.convert(json=json.dumps(filtered_output), escape=False))

    elif args.format == "csv":
        # we can assume ret has at least one element
        # CSV header
        print(",".join(ret[0].keys()))
        for line in ret:
            print(",".join([str(value) for value in line.values()]))


if __name__ == '__main__':
    main()
