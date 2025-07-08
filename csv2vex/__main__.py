import argparse
import csv2vex
from . import utils
def main():
    desc = f"csv2cdx v{csv2vex.__version__}"
    parser = argparse.ArgumentParser(description=desc)
    subparsers = parser.add_subparsers(dest='subcommand', required=False)

    template = subparsers.add_parser("template", help="Generates json configuration template file. Run csv2vex template -h for more details")
    template.add_argument("-name", type=str, required=False, help="Json configuration file name. Default: vex_config_template.")
    template.add_argument("-mp", type=str, required=False, help="make purl", action="store_true")

    build = subparsers.add_parser("build", help="Build VEX given args. Run csv2vex build -h for more details")

    #required arguments
    build.add_argument("-c", type=str, required=True, help="json configuration file")
    build.add_argument("-f", type=str, required=True, help="excel file")
    build.add_argument("-o", type=str, required=False, help="output file")
    build.add_argument("-mp", type=str, required=False, help="make purl", action="store_true")

    args = parser.parse_args()
    values = vars(args)
    comm = values.get('subcommand')
    if comm == 'build':
        utils.make_vex(values)
    elif comm == 'template':
        filename = values.get('name')
        make_purl = values.get('mp')
        utils.create_template_file(filename, make_purl)
    else:
        print('command not found')
    exit(0)

if __name__ == "__main__":
    main()