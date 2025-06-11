import os, sys, time, random, requests, socket

# Màu sắc
colors = [
    "\033[38;5;196m",  # Đỏ
    "\033[38;5;202m",  # Cam
    "\033[38;5;226m",  # Vàng
    "\033[38;5;205m",  # Cam
    "\033[38;5;199m",  # Hồng đậm
    "\033[38;5;46m",   # Xanh lá
    "\033[38;5;50m",   # Xanh light
    "\033[38;5;51m",   # Xanh cyan
    "\033[38;5;21m",   # Xanh dương
    "\033[38;5;201m"   # Hồng tím
]
error = colors[0] + "(" + colors[2] + "!" + colors[0] + ")" + colors[5]

# Banner
banner = [
    "╔═════════════════════════════════════════════╗",
    "║███╗   ███╗ █████╗ ███╗   ██╗██╗  ██╗███████╗║",
    "║████╗ ████║██╔══██╗████╗  ██║██║  ██║██╔════╝║",
    "║██╔████╔██║███████║██╔██╗ ██║███████║███████╗║",
    "║██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║╚════██║║",
    "║██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║███████║║",
    "║╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝║",
    "╚═════════════════════════════@MinhAnhs═══════╝"
]

def manhs_ip(url):
    response = requests.get(url)
    # Lấy IP từ tên miền trong nội dung trả về
    ip = socket.gethostbyname(response.text.strip())
    return ip

def glitch_line_color(line, glitch_rate=0.2):
    output = ""
    for char in line:
        if random.random() < glitch_rate and char not in [' ', '║', '╗', '╝', '╚', '╔', '═']:
            glitch_char = random.choice("🇻🇳!@#$%₫&*€¥=~<>?")
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

def main():
    url = "http://kiemtraip.com/raw.php"
    os.system('clear' if os.name != 'nt' else 'cls')

    # Hiệu ứng gõ dòng khởi động
    typing_effect(f"{error} Tool đang bảo trì...\n")
    typing_effect("Đang bảo trì sẽ cập nhật sau vài giờ\n")
    time.sleep(1)

    # Lấy IP 1 lần ban đầu
    ip = manhs_ip(url)

    try:
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            for line in banner:
                print(glitch_line_color(line, glitch_rate=0.02))
            print("\n" + colors[6] + f"-> IP hiện tại: {ip}")
            time.sleep(0.05)
    except KeyboardInterrupt:
        print("\n" + colors[0] + "[!] Đã thoát khỏi tool.")

if __name__ == "__main__":
    main()
