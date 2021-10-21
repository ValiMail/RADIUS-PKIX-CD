"""Perform authz based on access configuration and PKIX-CD."""
import argparse
import json
import sys

from dane_discovery.dane import DANE
from dane_discovery.identity import Identity
from dane_discovery.pki import PKI

from radius_pkix_cd.utility import Utility


description=("Authorize supplicants against the access configuration, "
             "using PKIX-CD for identity to trust anchor mapping."
             "\nExit codes:\n"
             "1: Missing trust map.\n"
             "2: Missing certificate file.\n"
             "3: Invalid called-station-id\n"
             "4: Live verify failed.\n"
             "5: IoT Registry check failed.")

parser = argparse.ArgumentParser(description=description)
parser.add_argument("--called", dest="called", required=True, 
                    help="Called-Station-Id.")
parser.add_argument("--calling", dest="calling", required=True, 
                    help="Callling-Station-Id.")
parser.add_argument("--certfile", dest="certfile", required=True, 
                    help="Certificate file presented by supplicant.")
parser.add_argument("--trustmap", dest="trustmap", required=True, 
                    help="Trust map, provided by pkix_cd_manage_trust.")
parser.add_argument("--live-verify", dest="live_verify", required=False, action="store_true", 
                    help="Verify directly against DNS, in addition to cached information.")
parser.add_argument("--require-registry", dest="require_registry", required=False, action="store_true", 
                    help="Set this to require IoT Registry revocation checks for all clients.")
parser.add_argument("--ns_override", dest="ns_override", required=False, help="Override system name server.")
parser.set_defaults(live_verify=False)
parser.set_defaults(require_registry=False)
parser.set_defaults(ns_override=None)



def main():
    """Verify against PKIX-CD and exit according to assertion."""
    args = parser.parse_args()
    # Load the trust map or bail.
    try:
        with open(args.trustmap) as f_on_disk:
            current_map = json.load(f_on_disk)
    except FileNotFoundError:
        print("Trust map not found: {}!".format(args.trustmap))
        sys.exit(1)
    
    # Load the presented certificate or bail.
    try:
        with open(args.certfile) as f_on_disk:
            cert_pem = f_on_disk.read()
    except FileNotFoundError:
        print("Certificate file not found: {}!".format(args.certfile))
        sys.exit(2)
    
    # Make sure that the called station is valid.
    ssid = args.called.split(":", 1)[1]
    if ssid not in current_map:
        print("Invalid called station: {} (no match {})".format(args.called, ssid))
        sys.exit(3)

    # Make sure that the identity is authorized to access the called station.
    if args.calling not in current_map[ssid]:
        print("Identity {} not allowed access to {}".format(args.calling, ssid))

    # Make sure that the AKI matches what PKIX-CD indicates.
    # Failures here may indicate cross-domain impersonation.
    aki = PKI.get_authority_key_id_from_certificate(cert_pem)
    if aki not in current_map[ssid][args.calling]:
        print("Presented certificate does not map to PKIX-CD authority certificate!")
        print("{} not in {}".format(aki, current_map[ssid][args.calling]))
        exit(4)

    # Next, we check the cert against the live DNS config!
    if args.live_verify:
        identity = Identity(args.calling, None, args.ns_override)
        success, reason = identity.validate_certificate(cert_pem)
        if not success:
            print("Failed PKIX-CD authentication: {}".format(reason))
            exit(5)

    # Finally, we check for IoT Registry revocation
    issued_by_iotregistry = Utility.check_iot_registry_issuance(cert_pem)
    registry_pass = True
    if args.require_registry and not issued_by_iotregistry:
        print("IoT Registry required, and this identity is not in the IoT Registry.")
        registry_pass = False
    if issued_by_iotregistry and Utility.check_iot_registry_revoked(cert_pem, args.ns_override):
        print("Certificate revoked by IoT Registry!")
        registry_pass = False
    if not registry_pass:
        exit(6)

    # If we've survived to this point, we win!
    exit(0)


if __name__ == "__main__":
    main()