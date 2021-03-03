"""Create a testing trust map for pkix_web_verify."""
import argparse
import json


parser = argparse.ArgumentParser()
parser.add_argument("--ssid")
parser.add_argument("--dnsname")
parser.add_argument("--aki")
parser.add_argument("--outfile")

def main():
    args = parser.parse_args()
    contents = {args.ssid: {args.dnsname:[args.aki.replace(":", "-").lower()]}}
    with open(args.outfile, "w") as out:
        out.write(json.dumps(contents))


if __name__ == "__main__":
    main()