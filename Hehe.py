import os, sys, time, random

# 7 màu ANSI cơ bản
colors = [
    "\033[38;5;196m",  # Đỏ
    "\033[38;5;202m",  # Cam
    "\033[38;5;226m",  # Vàng
    "\033[38;5;46m",   # Xanh lá
    "\033[38;5;51m",   # Xanh cyan
    "\033[38;5;21m",   # Xanh dương
    "\033[38;5;201m"   # Hồng tím
]
reset = "\033[0m"

error = colors[0] + "(" + colors[2] + "!" + colors[0] + ")" + reset

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

def typing_effect(text, delay=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

# Tạo dòng bị glitch + màu sắc nhấp nháy
def glitch_line_color(line, glitch_rate=0.12):
    output = ""
    for char in line:
        if random.random() < glitch_rate and char not in [' ', '║', '╗', '╝', '╚', '╔', '═']:
            glitch_char = random.choice("!@#$%^&*()_+=~<>?")
        else:
            glitch_char = char
        color = random.choice(colors)
        output += color + glitch_char + reset
    return output

# Xoá màn hình
os.system('clear' if os.name != 'nt' else 'cls')

# In thông báo khởi động
typing_effect(f"{error} Tool đang bảo trì...\n")
typing_effect("🌈 Đang khởi động hệ thống hiệu ứng màu động...\n")
time.sleep(1)

# Vòng lặp hiệu ứng vô hạn
try:
    while True:
        os.system('clear' if os.name != 'nt' else 'cls')
        for line in banner:
            print(glitch_line_color(line, glitch_rate=0.2))  # glitch nhanh hơn
        time.sleep(0.05)  # giảm thời gian cho nhanh hơn
except KeyboardInterrupt:
    print("\n" + colors[0] + "[!] Đã thoát khỏi tool." + reset)
