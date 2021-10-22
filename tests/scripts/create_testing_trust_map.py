"""Create a testing trust map for pkix_web_verify."""
import argparse
import json

from dane_discovery.dane import DANE

parser = argparse.ArgumentParser()
parser.add_argument("--ssid")
parser.add_argument("--dnsname")
parser.add_argument("--aki")
parser.add_argument("--outfile")
parser.add_argument("--cert_path")

def main():
    args = parser.parse_args()
    with open(args.cert_path) as cert:
        cert_hash = DANE.generate_sha_by_selector(cert.read(), "sha256", 0)
    contents = {args.ssid: {args.dnsname: 
                               {"akis": [args.aki.replace(":", "-").lower()],
                                "cert_hashes": [cert_hash]}}}
    with open(args.outfile, "w") as out:
        out.write(json.dumps(contents))


if __name__ == "__main__":
    main()