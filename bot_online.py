import discord
from discord import app_commands
from discord.ext import commands
import requests
import base64
import hashlib
import time
import os
import re
from dotenv import load_dotenv
from flask import Flask
import threading

# تحميل المتغيرات من ملف .env
load_dotenv()

TOKEN = os.getenv('DISCORD_TOKEN')
# مصادر فحص مجانية بدون API
HYBRID_ANALYSIS_API = "https://www.hybrid-analysis.com/api/v2"
KASPERSKY_API = "https://tip.kaspersky.com/api"

# إعداد Flask للاستضافة
app = Flask('')

@app.route('/')
def home():
    return "✅ Bot is running!"

def run_server():
    app.run(host='0.0.0.0', port=8080)

# إعداد البوت
intents = discord.Intents.default()
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'✅ تم تسجيل الدخول كـ {bot.user}')
    print(f'🔗 ID: {bot.user.id}')
    try:
        synced = await bot.tree.sync()
        print(f"✅ تم مزامنة {len(synced)} أمر/أوامر")
    except Exception as e:
        print(f"❌ خطأ في المزامنة: {e}")

@app_commands.command(name="scan", description="فحص ملف من عدة مصادر أمنية")
@app_commands.describe(file="الملف المراد فحصه")
async def scan(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer()
    
    try:
        # تحميل الملف
        file_data = await file.read()
        
        # حساب Hashes للملف
        md5_hash = hashlib.md5(file_data).hexdigest()
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        sha1_hash = hashlib.sha1(file_data).hexdigest()
        
        # إنشاء Embed للنتيجة
        embed = discord.Embed(
            title=f"🔍 نتيجة فحص: {file.filename}",
            color=0x0099ff
        )
        embed.add_field(name="📦 حجم الملف", value=f"{len(file_data):,} بايت ({len(file_data)/1024:.2f} KB)", inline=False)
        embed.add_field(name="🔑 MD5", value=f"`{md5_hash}`", inline=False)
        embed.add_field(name="🔑 SHA-256", value=f"`{sha256_hash}`", inline=False)
        embed.add_field(name="🔑 SHA-1", value=f"`{sha1_hash}`", inline=False)
        
        # فحص من Hybrid Analysis (مجاني)
        try:
            await interaction.followup.send("⏳ جاري الفحص من Hybrid Analysis...")
            
            ha_url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
            headers = {
                "api-key": "",
                "User-Agent": "Falcon Sandbox"
            }
            params = {"hash": sha256_hash}
            
            # محاولة الفحص
            try:
                ha_response = requests.get(ha_url, headers=headers, params=params, timeout=10)
                if ha_response.status_code == 200:
                    data = ha_response.json()
                    if len(data) > 0:
                        result = data[0]
                        threat_score = result.get('threat_score', 0)
                        verdict = result.get('verdict', 'unknown')
                        
                        if threat_score > 50 or verdict == 'malicious':
                            embed.color = 0xff0000
                            embed.add_field(name="⚠️ Hybrid Analysis", value=f"**خطير!** - درجة التهديد: {threat_score}/100", inline=False)
                        else:
                            embed.color = 0x00ff00
                            embed.add_field(name="✅ Hybrid Analysis", value=f"**آمن** - درجة التهديد: {threat_score}/100", inline=False)
                    else:
                        embed.add_field(name="❓ Hybrid Analysis", value="الملف مو موجود في قاعدة البيانات", inline=False)
                else:
                    embed.add_field(name="❌ Hybrid Analysis", value="خطأ في الاتصال", inline=False)
            except:
                embed.add_field(name="⏳ Hybrid Analysis", value="ما تم الفحص", inline=False)
                
        except:
            pass
        
        # فحص من Google Safe Browsing (إذا الملف نصي)
        if file.filename.endswith(('.js', '.py', '.txt', '.html')):
            try:
                content = file_data.decode('utf-8', errors='ignore')
                
                # فحص يدوي للأكاد المشبوهة
                suspicious_patterns = [
                    (r'eval\s*\(', 'دالة eval مشبوهة'),
                    (r'exec\s*\(', 'دالة exec مشبوهة'),
                    (r'__import__\s*\(', 'استيراد ديناميكي'),
                    (r'subprocess', 'تنفيذ أوامر النظام'),
                    (r'os\.system', 'تنفيذ أوامر النظام'),
                    (r'base64\.b64decode', 'فك Base64'),
                    (r'atob\s*\(', 'فك Base64 (atob)'),
                    (r'document\.cookie', 'سرقة الكوكيز'),
                    (r'window\.location', 'إعادة توجيه'),
                    (r'fetch\s*\(', 'طلبات شبكة'),
                    (r'XMLHttpRequest', 'طلبات AJAX'),
                ]
                
                found_threats = []
                for pattern, desc in suspicious_patterns:
                    if re.search(pattern, content):
                        found_threats.append(desc)
                
                if found_threats:
                    embed.color = 0xffaa00
                    threats_text = '\n'.join([f"⚠️ {t}" for t in found_threats[:5]])
                    embed.add_field(name="🚨 تحليل الكود", value=threats_text, inline=False)
                else:
                    embed.add_field(name="✅ تحليل الكود", value="ما فيه أنماط مشبوهة واضحة", inline=False)
                    
            except:
                pass
        
        # روابط الفحص
        embed.add_field(name="🔗 فحص يدوي", value=(
            f"[VirusTotal](https://www.virustotal.com/gui/file/{sha256_hash})\n"
            f"[Hybrid Analysis](https://www.hybrid-analysis.com/search?query={sha256_hash})\n"
            f"[Any.Run](https://any.run/report/)\n"
            f"[FileScan.IO](https://www.filescan.io/search?hash={sha256_hash})"
        ), inline=False)
        
        embed.set_footer(text="💡 ملاحظة: استخدم الروابط لفحص أعمق من مصادر متعددة")
        
        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        await interaction.followup.send(f"❌ حدث خطأ: {str(e)}")

@app_commands.command(name="deobfuscate", description="فك تلغيم كود JavaScript/Python")
@app_commands.describe(file="الملف المراد فك تلغيمه")
async def deobfuscate(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer()
    
    try:
        # قراءة محتوى الملف
        file_data = await file.read()
        
        try:
            content = file_data.decode('utf-8')
        except:
            await interaction.followup.send("❌ الملف يجب أن يكون نصي (JS, PY, TXT)")
            return
        
        # التحقق من نوع التلغيم
        deobfuscated = content
        
        # فك تلغيم Base64
        if 'base64' in content.lower() or 'atob' in content.lower():
            try:
                # البحث عن سلاسل Base64
                b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
                matches = re.findall(b64_pattern, content)
                
                decoded_parts = []
                for match in matches:
                    try:
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                        if any(c.isalpha() for c in decoded):  # تأكد أنه نص حقيقي
                            decoded_parts.append(f"Base64 Decoded:\n```{decoded[:500]}```")
                    except:
                        pass
                
                if decoded_parts:
                    deobfuscated = '\n\n'.join(decoded_parts)
            except:
                pass
        
        # فك تلغيم eval/execute
        if 'eval(' in content or 'exec(' in content:
            # استخراج الكود داخل eval/exec
            eval_pattern = r'(?:eval|exec)\s*\((.*?)\)'
            matches = re.findall(eval_pattern, content, re.DOTALL)
            
            if matches:
                deobfuscated += "\n\n📌 Code inside eval/exec:\n"
                for i, match in enumerate(matches[:3]):  # أول 3 مرات فقط
                    deobfuscated += f"```javascript\n{match[:300]}\n```\n"
        
        # فك تلغيم string manipulation
        if 'String.fromCharCode' in content or 'chr(' in content:
            # استخراج الأرقام من fromCharCode
            charcode_pattern = r'String\.fromCharCode\(([^)]+)\)'
            matches = re.findall(charcode_pattern, content)
            
            if matches:
                deobfuscated += "\n\n📌 Decoded fromCharCode:\n"
                for match in matches[:2]:
                    try:
                        chars = [int(x.strip()) for x in match.split(',')]
                        decoded = ''.join(chr(c) for c in chars if 32 <= c < 127)
                        deobfuscated += f"```{decoded[:300]}\n```\n"
                    except:
                        pass
        
        # إضافي: فحص PowerShell obfuscation
        if 'powershell' in content.lower() or 'cmd' in content.lower():
            ps_patterns = [
                (r'-EncodedCommand\s+([A-Za-z0-9+/=]{20,})', 'PowerShell EncodedCommand'),
                (r'-enc\s+([A-Za-z0-9+/=]{20,})', 'PowerShell -enc'),
            ]
            
            for pattern, desc in ps_patterns:
                ps_matches = re.findall(pattern, content)
                if ps_matches:
                    deobfuscated += f"\n\n📌 {desc}:\n"
                    for match in ps_matches[:2]:
                        try:
                            decoded = base64.b64decode(match).decode('utf-16', errors='ignore')
                            deobfuscated += f"```\n{decoded[:500]}\n```\n"
                        except:
                            deobfuscated += f"`{match[:200]}...`\n"
        
        # إضافي: فحص Hex encoding
        hex_pattern = r'\\x([0-9a-fA-F]{2})'
        hex_matches = re.findall(hex_pattern, content)
        if len(hex_matches) > 5:  # إذا فيه أكثر من 5 أحرف hex
            try:
                decoded_hex = ''.join(chr(int(x, 16)) for x in hex_matches)
                deobfuscated += f"\n\n📌 Decoded from Hex:\n```{decoded_hex[:500]}```"
            except:
                pass
        
        # إرسال النتيجة
        if len(deobfuscated) > 1900:
            # إذا كان طويل جداً، أرسل كملف
            deobfuscated_file = "deobfuscated_output.txt"
            with open(deobfuscated_file, 'w', encoding='utf-8') as f:
                f.write(deobfuscated)
            
            await interaction.followup.send(
                f"✅ تم فك التلغيم (الملف طويل، إليك النتيجة كاملة):",
                file=discord.File(deobfuscated_file)
            )
            os.remove(deobfuscated_file)
        else:
            embed = discord.Embed(
                title="🔓 نتيجة فك التلغيم",
                description=f"```javascript\n{deobfuscated[:1900]}\n```",
                color=0x00ff00
            )
            await interaction.followup.send(embed=embed)
        
    except Exception as e:
        await interaction.followup.send(f"❌ حدث خطأ: {str(e)}")

# إضافة الأوامر للشجرة
bot.tree.add_command(scan)
bot.tree.add_command(deobfuscate)

# تشغيل البوت مع Flask
if __name__ == "__main__":
    # تشغيل Flask في thread منفصل
    threading.Thread(target=run_server).start()
    
    # تشغيل البوت
    bot.run(TOKEN)
