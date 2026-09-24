"""生成应用图标：与界面同色系的「网络 + 诊断」图形。

输出 icon.ico（多尺寸），供 PyInstaller 打包使用。
"""
import os

from PIL import Image, ImageDraw

ACCENT = (43, 127, 255)
ACCENT_DK = (31, 111, 235)
OK = (0, 180, 42)
FAIL = (245, 63, 63)
WHITE = (255, 255, 255)

HERE = os.path.dirname(os.path.abspath(__file__))   # 本脚本所在目录（tools/）
ROOT = os.path.dirname(HERE)                        # 项目根
SIZE = 512
SS = 4  # 超采样倍数，保证小尺寸下边缘平滑


def rounded_rect(draw, box, radius, fill):
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def make_icon() -> Image.Image:
    s = SIZE * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 背景：圆角方形 + 蓝色渐变（用多条横线模拟）
    radius = int(s * 0.22)
    for i in range(s):
        t = i / s
        r = int(ACCENT[0] * (1 - t) + ACCENT_DK[0] * t)
        g = int(ACCENT[1] * (1 - t) + ACCENT_DK[1] * t)
        b = int(ACCENT[2] * (1 - t) + ACCENT_DK[2] * t)
        d.line([(0, i), (s, i)], fill=(r, g, b, 255))
    # 抠回圆角
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=radius, fill=255)
    img.putalpha(mask)

    d = ImageDraw.Draw(img)
    cx = s / 2

    # 网络拓扑：三个节点 + 连线
    top = (cx, s * 0.28)
    bl = (s * 0.28, s * 0.62)
    br = (s * 0.72, s * 0.62)
    lw = max(2, int(s * 0.022))
    for a, b in ((top, bl), (top, br), (bl, br)):
        d.line([a, b], fill=(255, 255, 255, 150), width=lw)

    nr = int(s * 0.068)
    for p, color in ((top, WHITE), (bl, WHITE), (br, WHITE)):
        d.ellipse([p[0] - nr, p[1] - nr, p[0] + nr, p[1] + nr], fill=color)

    # 右下角：放大镜表示「诊断」，镜内一个红点表示发现问题
    # 整体收进画布内，避免手柄被圆角裁掉
    mg_r = int(s * 0.155)
    mc = (s * 0.665, s * 0.665)
    ring = max(3, int(s * 0.030))
    d.ellipse([mc[0] - mg_r, mc[1] - mg_r, mc[0] + mg_r, mc[1] + mg_r],
              outline=WHITE, width=ring)
    # 手柄（沿 45° 方向，长度控制在画布内）
    hx1 = mc[0] + mg_r * 0.78
    hy1 = mc[1] + mg_r * 0.78
    hx2 = mc[0] + mg_r * 1.62
    hy2 = mc[1] + mg_r * 1.62
    d.line([(hx1, hy1), (hx2, hy2)], fill=WHITE, width=int(ring * 1.3))
    # 镜内红点
    dot = int(s * 0.042)
    d.ellipse([mc[0] - dot, mc[1] - dot, mc[0] + dot, mc[1] + dot], fill=FAIL)

    return img.resize((SIZE, SIZE), Image.LANCZOS)


def main():
    img = make_icon()
    png = os.path.join(ROOT, "icon.png")
    img.save(png)
    ico = os.path.join(ROOT, "icon.ico")
    # 打包成多尺寸 ico，任务栏/资源管理器在不同场景会自动选合适尺寸
    img.save(ico, sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
    print("已生成:", png)
    print("已生成:", ico)
    for f in (png, ico):
        print(f"  {os.path.basename(f)}  {os.path.getsize(f):,} 字节")


if __name__ == "__main__":
    main()
