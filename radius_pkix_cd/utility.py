"""Utility functions for radius_pkix_cd."""
import json
import re

from dane_discovery.pki import PKI
from dane_discovery.dane import DANE


class Utility:
    """Various utility functions found here."""

    iot_registry_org_domains = ["iotregistry.ca"]

    @classmethod
    def update_trust_store_file(cls, path, trust_map):
        """Update the trust store file.

        This function will first compare the file
        on disk to what's to be written, and only 
        write the file if it's different than what's
        already on disk.

        Args:
            path (str): Path to trust store file.
            trust_map (dict):This is a dictionary where 
                the first-level key is the realm.
                The value for the first-level key is a 
                dictionary where the key is the DNS
                name and the value is a list of valid
                authorityKeyIDs.
                {"MySSID": 
                    {"my._device.example": 
                        ["AKI1",
                         "AnotherAKI"]
                    }
                }
        
        Return: True if file was updated, False otherwise.
        """
        try:
            with open(path) as f_on_disk:
                current_map = json.load(f_on_disk)
        except FileNotFoundError:
            current_map = {}
        except json.decoder.JSONDecodeError:
            current_map = {}
        if not current_map == trust_map:
            with open(path, 'w') as f_on_disk:
                json.dump(trust_map, f_on_disk)
                print("Updated trust store at {}".format(path))
                return True
        return False
    
    @classmethod
    def get_authz_config(cls, path):
        """Return dict representing authz configuration.
        
        The format of the file is expected to be pipe- 
        delimited REALM|DNSNAME. If you use pipes in your 
        SSID names... sorry. Also, don't start your SSID 
        with a space. Because that won't work either.

        This function organizes permitted Called-Station-IDs 
        by DNSName.

        If there are incorrectly-formatted lines in the file,
        the problem line number will be printed to stdout and
        the process will continue.
        
        Args:
            path (str): Path to authz file.
            
        Return:
            dict: {"my._device.example": ["MySSID", "OtherSSID"]}
        """
        authz_config = {}
        with open(path) as authz_file:
            line_no = 0
            for line in authz_file.readlines():
                line = line.strip(" ").strip("\n")
                line_no += 1
                if not line:
                    # Catch empty lines
                    continue
                line_parts = line.split("|")
                if len(line_parts) != 2:
                    print("Incorrectly formatted line: {}".format(line_no))
                realm = line_parts[0]
                try:
                    identity_name = line_parts[1]
                    cls.verify_dns_name(identity_name)
                except ValueError as err:
                    print("Bad ID name on line {}: {}".format(line_no, err))
                    continue
                if identity_name not in authz_config:
                    authz_config[identity_name] = [realm]
                else:
                    authz_config[identity_name].append(realm)
        return authz_config

    
    @classmethod
    def verify_dns_name(cls, dns_name):
        """Ensure that ```dns_name`` conforms to RFC 1123 constraints.

        Allowable length: 255 chars.

        Characters: a-z, 1-9, -_.

        Args:
            dns_name (str): DNS name to validate.

        Return:
            None

        Raise:
            ValueError
        """
        dns_name = dns_name.rstrip(".")
        if cls.is_it_an_ip(dns_name):
            errmsg = "'{}' is a bad hostname (is it an IP address?)!".format(dns_name)
            raise ValueError(errmsg)
        split_at_dot = dns_name.split(".")
        pattern = re.compile("^([A-Za-z0-9_-]+)$")
        for x in split_at_dot:
            if not pattern.match(x):
                errmsg = "'{}' is a bad hostname!".format(dns_name)
                raise ValueError("Hostname invalid!")

    @classmethod
    def is_it_an_ip(cls, dns_name):
        """Return True if it's an IP, False otherwise."""
        split_at_dot = dns_name.split(".")
        if len(split_at_dot) != 4:
            return False
        try:
            for x in split_at_dot:
                if not 0 < int(x) < 255:
                    return False
        except ValueError:
            return False
        return True

    @classmethod
    def update_ca_file(cls, file_name, pem_certs):
        """Write all CA certificates to a file."""
        with open(file_name, "wb") as ca_file:
            ca_file.write(b"\n".join(pem_certs))

    @classmethod
    def check_iot_registry_issuance(cls, cert_pem):
        """Return True if the certificate was issued by IoT Registry."""
        cert_meta = PKI.get_cert_meta(cert_pem)
        common_name = cert_meta["subject"]["commonName"]
        for registry_domain in cls.iot_registry_org_domains:
            if cls.dnsname_in_domain(common_name, registry_domain):
                return True
        return False

    @classmethod
    def check_iot_registry_revoked(cls, cert_pem, ns_override=None):
        """Return True if the certificate has been revoked by the IoT registry.
        
        We expect to find exactly one TLSA RR for the identity in the IoT registry.
        
        That TLSA record must be delivered with DNSSEC, and it must be a 
        ``3 0 1`` representation.

        The SHA256 hash must match the presented certificate.
        """
        cert_meta = PKI.get_cert_meta(cert_pem)
        registry_dns_name = cert_meta["subject"]["commonName"]
        registry_entries = DANE.get_tlsa_records(registry_dns_name, nsaddr=ns_override)
        if not registry_entries:
            print("No IoT registry entry for identity!")
            return True
        registry_entry = registry_entries[0]
        reg_txt = str(registry_entry)
        if not (registry_entry["certificate_usage"] == 3 
                and registry_entry["selector"] == 0
                and registry_entry["matching_type"] == 1):
            print("Unexpected TLSA record format from registry: {}".format(reg_txt))
            return True
        expected_sha = DANE.generate_sha_by_selector(cert_pem, "sha256", 0)
        if not expected_sha == registry_entry["certificate_association"]:
            print("Hash mismatch: Registry: {} != Cert: {}".format(registry_entry["certificate_association"], expected_sha))
            return True
        return False
        
    @classmethod
    def domain_str_to_labels(cls, domain_name):
        """Return a list of domain name labels, in reverse-DNS order."""
        labels = domain_name.rstrip(".").split(".")
        labels.reverse()
        return labels

    @classmethod
    def dnsname_in_domain(cls, dns_name, domain_name):
        """Return True if dns_name falls under domain_name, else False.
        
        Forces to lowercase for comparison, since DNS is case-insensitive"""
        dns_name_parts = cls.domain_str_to_labels(dns_name.lower())
        domain_name_parts = cls.domain_str_to_labels(domain_name.lower())
        if len(dns_name_parts) <= len(domain_name_parts):
            return False
        for domain_label in domain_name_parts:
            dns_label = dns_name_parts.pop(0)
            if dns_label != domain_label:
                return False
        return True