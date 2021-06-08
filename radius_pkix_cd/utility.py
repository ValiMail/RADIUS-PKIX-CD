"""Utility functions for radius_pkix_cd."""
import json
import re


class Utility:
    """Various utility functions found here."""

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