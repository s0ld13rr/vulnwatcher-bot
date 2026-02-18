import os, httpx, yaml, sqlite3, asyncio, logging, re
from dotenv import load_dotenv

load_dotenv()

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s | %(levelname)-7s | %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("VulnBot")


def escape_md(text):
    if not text: return ""
    return re.sub(r'([\_\*\[\]\(\)\~\`\>\#\+\-\=\|\\\{\}\.\!])', r'\\\1', str(text))


class Style:
    SEVERITY = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🟢 LOW"
    }


class VulnWatcher:
    def __init__(self):
        self.api_key = os.getenv("PDCP_API_KEY")
        self.tg_token = os.getenv("TG_BOT_TOKEN")
        self.chat_id = os.getenv("TG_CHAT_ID")
        self.min_cvss = float(os.getenv("MIN_CVSS", 7.5))
        self.api_url = "https://api.projectdiscovery.io/v2/vulnerability/search"
        self.db = sqlite3.connect('vuln_states.db')
        self._init_db()
        self.is_first_run = self._check_if_first_run()

    def _init_db(self):
        with self.db:
            self.db.execute('CREATE TABLE IF NOT EXISTS states (cve_id TEXT PRIMARY KEY, poc INT, exploit INT)')

    def _check_if_first_run(self):
        res = self.db.execute('SELECT COUNT(*) FROM states').fetchone()
        return res[0] == 0

    async def send_tg(self, text):
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        async with httpx.AsyncClient() as client:
            try:
                r = await client.post(url, json={
                    "chat_id": self.chat_id, 
                    "text": text, 
                    "parse_mode": "MarkdownV2", 
                    "disable_web_page_preview": True
                })
                if r.status_code != 200:
                    logger.error(f"❌ TG Error: {r.status_code} | {r.text}")
            except Exception as e:
                logger.error(f"❌ Network Error: {e}")

    async def check_cycle(self):
        with open("targets.yaml", "r") as f:
            config = yaml.safe_load(f)

        queries = config.get('queries', [])
        headers = {"X-PDCP-Key": self.api_key} if self.api_key else {}
        success_count = 0
        
        async with httpx.AsyncClient(headers=headers, timeout=30) as client:
            for idx, q in enumerate(queries, 1):
                if idx > 1: await asyncio.sleep(5) 
                try:
                    r = await client.get(self.api_url, params={"q": q, "limit": 10})
                    if r.status_code == 200:
                        results = r.json().get('results', [])
                        valid_cves = [v for v in results if v.get('doc_type') == 'cve']
                        logger.info(f"[{idx}/{len(queries)}] 🔍 {q.ljust(15)} | ✅ OK ({len(valid_cves)})")
                        for v in valid_cves:
                            await self.process_vulnerability(v, q)
                        success_count += 1
                except Exception as e:
                    logger.error(f"❌ Error {q}: {e}")

        if self.is_first_run and success_count > 0:
            logger.info("🚀 Синхронизация завершена. Мониторинг активен.")

    async def process_vulnerability(self, v, label):
        cve_id = v.get('cve_id')
        if not cve_id or v.get('doc_type') != 'cve': return

        cvss = float(v.get('cvss_score', 0))
        has_poc = 1 if (v.get('is_poc') or v.get('poc_count', 0) > 0) else 0
        exploit_seen = 1 if v.get('is_exploit_seen') else 0
        
        row = self.db.execute('SELECT poc, exploit FROM states WHERE cve_id=?', (cve_id,)).fetchone()

        if not row:
            with self.db:
                self.db.execute('INSERT INTO states VALUES (?, ?, ?)', (cve_id, has_poc, exploit_seen))
            if self.is_first_run: return

            if cvss >= self.min_cvss or has_poc:
                await self.notify(v, label, "NEW VULNERABILITY DETECTED")
        else:
            old_poc, old_exploit = row
            change = None
            if exploit_seen > old_exploit: change = "🚨 EMERGENCY: EXPLOIT IN THE WILD"
            elif has_poc > old_poc: change = "🚀 NEW PoC RELEASED"
            
            if change:
                await self.notify(v, label, change)
                with self.db:
                    self.db.execute('UPDATE states SET poc=?, exploit=? WHERE cve_id=?', (has_poc, exploit_seen, cve_id))

    async def notify(self, v, label, header):
       
        severity = v.get('severity', 'low').lower()
        sev_label = Style.SEVERITY.get(severity, "⚪ UNKNOWN")
        
        epss_raw = v.get('epss_score', 0)
        
        cwe_list = v.get('cwe', [])
        cwe = cwe_list[0] if cwe_list else "N/A"
        
        desc = v.get('description', 'No description available.')
        if len(desc) > 400: desc = desc[:400] + "..."

       
        poc_status = "✅" if (v.get('is_poc') or v.get('poc_count', 0) > 0) else "❌"
        exploit_status = "🔥 YES" if v.get('is_exploit_seen') else "No"

        
        e_header = escape_md(header)
        e_product = escape_md(label.upper())
        e_cve_id = escape_md(v.get('cve_id'))
        e_cvss = escape_md(v.get('cvss_score'))
        e_epss = escape_md(f"{float(epss_raw)*100:.2f}%")
        e_cwe = escape_md(cwe)
        e_desc = escape_md(desc)
        
        
        divider = escape_md("━━━━━━━━━━━━━━━━━━")
        pipe = escape_md("|")

        
        msg = (
            f"{e_header}\n"
            f"{divider}\n"
            f"🛡 *{sev_label}*\n\n"
            f"📦 *Asset:* `{e_product}`\n"
            f"🆔 *ID:* [{e_cve_id}](https://www.opencve.io/cve/{e_cve_id})\n"
            f"📊 *CVSS:* `{e_cvss}` {pipe} *EPSS:* `{e_epss}`\n"
            f"🧬 *Type:* `{e_cwe}`\n"
            f"🛠 *PoC:* {poc_status} {pipe} *Exploit:* {exploit_status}\n\n"
            f"📖 *Summary:*\n_{e_desc}_"
        )
        await self.send_tg(msg)


async def main():
    bot = VulnWatcher()
    await bot.check_cycle()

if __name__ == "__main__":
    asyncio.run(main())
