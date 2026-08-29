from pathlib import Path
from shutil import copyfile
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "manager" / "AppMux.Manager" / "Assets" / "AppMux.png"
OUT = SOURCE.parent
PUBLIC = ROOT / "assets"

icon = Image.open(SOURCE).convert("RGBA")
if icon.size != (1024, 1024):
    raise SystemExit(f"canonical AppMux.png must be 1024x1024, got {icon.size}")

PUBLIC.mkdir(parents=True, exist_ok=True)
copyfile(SOURCE, PUBLIC / "appmux-icon.png")
icon.save(
    OUT / "AppMux.ico",
    format="ICO",
    sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
)

banner = Image.new("RGB", (1200, 360), "white")
mark = icon.resize((300, 300), Image.Resampling.LANCZOS)
banner.paste(mark, (60, 30), mark)
draw = ImageDraw.Draw(banner)
font_dir = Path("C:/Windows/Fonts")
word_font = ImageFont.truetype(str(font_dir / "seguisb.ttf"), 112)
tag_font = ImageFont.truetype(str(font_dir / "segoeui.ttf"), 25)
app = "App"
app_width = draw.textlength(app, font=word_font)
draw.text((385, 82), app, fill="#07163f", font=word_font, anchor="la")
draw.text((385 + app_width - 4, 82), "Mux", fill="#1557f2", font=word_font, anchor="la")
draw.text((392, 230), "Layered app instances, simplified.", fill="#68728b", font=tag_font, anchor="la")
banner.save(PUBLIC / "appmux-brand.png", optimize=True)
print(OUT / "AppMux.ico")
