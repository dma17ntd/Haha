import os, sys, time, random, requests, socket
from datetime import datetime
import speedtest

# Màu
colors = [
    "\033[38;5;196m", "\033[38;5;202m", "\033[38;5;226m",
    "\033[38;5;199m", "\033[38;5;154m", "\033[38;5;214m",
    "\033[38;5;244m", "\033[38;5;155m", "\033[38;5;157m",
    "\033[38;5;46m", "\033[38;5;51m", "\033[38;5;21m",
    "\033[38;5;201m", "\033[38;5;205m", "\033[38;5;50m",
]
error = colors[0] + "(" + colors[2] + "!" + colors[0] + ")"

banner = [
    "╔═════════════════════════════════════════════╗",
    "║███╗   ███╗ █████╗ ███╗   ██╗██╗  ██╗███████╗║",
    "║████╗ ████║██╔══██╗████╗  ██║██║  ██║██╔════╝║",
    "║██╔████╔██║███████║██╔██╗ ██║███████║███████╗║",
    "║██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║╚════██║║",
    "║██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║███████║║",
    "║╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝║",
    "╚═════════════════════════════════════════════╝"
]

def manhs_ip(url):
    response = requests.get(url)
    ip = socket.gethostbyname(response.text.strip())
    return ip

def glitch_line_color(line, glitch_rate=0.2):
    output = ""
    for char in line:
        if random.random() < glitch_rate and char not in [' ', '║', '╗', '╝', '╚', '╔', '═']:
            glitch_char = random.choice("!@#$%^&*()_+=~<>?")
        else:
            glitch_char = char
        color = random.choice(colors)
        output += color + glitch_char
    return output

def typing_effect(text, delay=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def get_speed_info():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download = st.download() / 1_000_000  # Mbps
        upload = st.upload() / 1_000_000      # Mbps
        ping = st.results.ping
        return f"{download:.2f} Mbps ↓ | {upload:.2f} Mbps ↑ | {ping:.0f} ms"
    except:
        return "Không đo được tốc độ mạng."

def main():
    url = "http://kiemtraip.com/raw.php"
    os.system('clear' if os.name != 'nt' else 'cls')

    typing_effect(f"{error} Tool đang bảo trì...\n")
    typing_effect("Đang bảo trì tool - Tool sẽ cập nhật sau ít phút\n")
    time.sleep(1)

    ip = manhs_ip(url)
    net_speed = get_speed_info()

    try:
        while True:
            now = datetime.now().strftime("%H:%M:%S | %d-%m-%Y")
            os.system('clear' if os.name != 'nt' else 'cls')

            for line in banner:
                print(glitch_line_color(line, glitch_rate=0.002))
            
            # In thêm thông tin bên dưới
            print()
            print(colors[2] + f"Thời gian hiện tại: {now}")
            print(colors[4] + f"Địa chỉ IP: {ip}")
            print(colors[5] + f"Tốc độ mạng: {net_speed}")

            time.sleep(0.3)
    except KeyboardInterrupt:
        print("\n" + colors[0] + "[!] Đã thoát khỏi tool.")

if __name__ == "__main__":
    main()
