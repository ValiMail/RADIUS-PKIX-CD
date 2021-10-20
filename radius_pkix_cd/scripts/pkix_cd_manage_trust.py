"""Manage trust map and CA bundle for RADIUS server."""
import argparse

from dane_discovery.identity import Identity
from dane_discovery.pki import PKI

from radius_pkix_cd.utility import Utility


description=("Manage trust map for radius_pkix_cd tool.\n"
             "Infile format is pipe delimited:\n"
             "CalledStation|my._device.example.com\n"
             "...where CalledStation is the Called-Station-Id and "
             "my._device.example.com is the name of the "
             "device allowed to access the Called-Station-Id. "
             "Devices may be associated with multiple CalledStations.")

parser = argparse.ArgumentParser(description=description)
parser.add_argument("--infile", dest="infile", required=True, help="Network access list.")
parser.add_argument("--trustmap", dest="trustmap", required=True, help="Trust map (outfile) for pkix_cd_verify.")
parser.add_argument("--cacerts", dest="cacerts", required=True, help="Outfile for CA certificates.")
parser.add_argument("--ns_override", dest="ns_override", required=False, help="Override system name server.")
parser.set_defaults(ns_override=None)


def main():
    """Wrap the process of managing the trust map and CA certs files."""
    args = parser.parse_args()
    trust_map = Utility.get_authz_config(args.infile)
    configured_trust = {}
    ca_certificates = set([])
    for dnsname, realms in trust_map.items():
        for realm in realms:
            if realm not in configured_trust:
                configured_trust[realm] = {dnsname: []}
            else:
                if not dnsname in configured_trust[realm]:
                    configured_trust[realm][dnsname] = []
        identity = Identity(dnsname, None, args.ns_override)
        akis = []
        try:
            for _, cert in identity.get_all_certificates(filters=["PKIX-CD"]).items():
                akis.append(PKI.get_authority_key_id_from_certificate(cert))
                ca_certificates.add(identity.get_pkix_cd_trust_chain(cert)["root"])
            configured_trust[realm][dnsname] = akis
        except (ValueError, KeyError) as err:
            print("Recoverable error: {}".format(err))
            print("Continuing...")
            continue
    if Utility.update_trust_store_file(args.trustmap, configured_trust):
        print("Updated trust store file.")
        Utility.update_ca_file(args.cacerts, [x for x in ca_certificates])
    else:
        print("No update to trust store file.")


if __name__ == "__main__":
    main()