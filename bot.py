import os
import logging
import re
import requests
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes

# .env ဖိုင်ရှိလျှင် ဖတ်ရန် (Local development အတွက်)
# Render ပေါ်ရောက်လျှင် Dashboard က Environment Variables ကို အလိုအလျောက် သုံးသွားပါမည်။
load_dotenv()

# --- CONFIGURATION ---
# Environment Variables မှ အချက်အလက်များကို ဆွဲယူခြင်း
SCANNER_TOKEN = os.getenv("SCANNER_BOT_TOKEN")
REPORTER_TOKEN = os.getenv("REPORTER_BOT_TOKEN") # ကြားခံ Bot (သို့) Scanner Bot Token အတူတူသုံးနိုင်သည်
TARGET_CHAT_ID = os.getenv("TARGET_CHAT_ID")     # အကြောင်းကြားစာ လက်ခံမည့် Group/User ID
VT_API_KEY = os.getenv("VT_API_KEY")             # VirusTotal API Key

# Error များကို ခြေရာခံနိုင်ရန် Logging သတ်မှတ်ခြင်း
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

async def check_url_virustotal(url):
    """VirusTotal API သုံးပြီး URL ကို စစ်ဆေးသည့် Function"""
    if not VT_API_KEY:
        logger.error("VirusTotal API Key missing!")
        return None

    api_url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": url}
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    
    try:
        # URL ကို VirusTotal ဆီ Submit လုပ်ခြင်း
        response = requests.post(api_url, data=payload, headers=headers)
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            
            # ခေတ္တစောင့်ပြီး Analysis Result ကို ပြန်တောင်းခြင်း
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report = requests.get(analysis_url, headers=headers)
            return report.json()
    except Exception as e:
        logger.error(f"VirusTotal API Error: {e}")
    return None

async def send_alert_to_admin(alert_text):
    """Reporter Bot ကို သုံးပြီး သတ်မှတ်ထားသော Chat ID ထံ သတင်းပို့ခြင်း"""
    url = f"https://api.telegram.org/bot{REPORTER_TOKEN}/sendMessage"
    payload = {
        "chat_id": TARGET_CHAT_ID,
        "text": alert_text,
        "parse_mode": "HTML"
    }
    try:
        requests.post(url, data=payload)
    except Exception as e:
        logger.error(f"Alert Sending Error: {e}")

async def handle_group_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Group ထဲက Message များကို စောင့်ကြည့်ပြီး Link ပါလျှင် စစ်ဆေးခြင်း"""
    if not update.message or not update.message.text:
        return

    message_text = update.message.text
    # Regex သုံးပြီး URL များကို ရှာဖွေခြင်း
    urls = re.findall(r'(https?://[^\s]+)', message_text)
    
    for url in urls:
        logger.info(f"Scanning URL found in group: {url}")
        result = await check_url_virustotal(url)
        
        if result:
            attributes = result['data']['attributes']
            stats = attributes.get('stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)

            # Malicious (သို့) Suspicious တွေ့ရှိပါက Admin ထံ သတင်းပို့မည်
            if malicious > 0 or suspicious > 0:
                alert_body = (
                    f"⚠️ <b>Potentially Malicious Link Detected!</b>\n\n"
                    f"<b>From Group:</b> {update.message.chat.title}\n"
                    f"<b>Sent By:</b> @{update.message.from_user.username if update.message.from_user.username else 'Unknown'}\n"
                    f"<b>URL:</b> <code>{url}</code>\n"
                    f"<b>Security Score:</b> {malicious} vendors flagged as malicious."
                )
                await send_alert_to_admin(alert_body)
                logger.warning(f"Malicious link detected and reported: {url}")

def main():
    """Bot ကို စတင်နှိုးခြင်း"""
    if not SCANNER_TOKEN:
        logger.error("SCANNER_BOT_TOKEN is not set!")
        return

    # Application တည်ဆောက်ခြင်း
    application = Application.builder().token(SCANNER_TOKEN).build()
    
    # Message အားလုံးကို ဖတ်ပြီး handle_group_message function ဆီ ပို့ပေးမည့် Handler
    application.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_group_message))
    
    logger.info("Bot is starting and monitoring links...")
    # Render ပေါ်တွင် Run ရန် Polling စနစ် (Webhook ပြောင်းလိုပါက နောက်ပိုင်းတွင် လုပ်ဆောင်နိုင်သည်)
    application.run_polling()

if __name__ == '__main__':
    main()