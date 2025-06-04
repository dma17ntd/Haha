import os, sys, requests, socket
do = "\033[1;38;5;9m"
vang = "\033[1;38;5;11m"
error = do + "(" + vang + "!" + do + ")"
os.system('clear')
def manhs_ip(url):
  response = requests.get(url)
  manhs_ips = socket.gethostbyname(response.text.strip())
  return manhs_ips
url = "http://kiemtraip.com/raw.php"
ip = manhs_ip
print(f"{error} Tool đang bảo trì")
print(f"{ip}")
