# ZAMIN PhishHunter

A responsive phishing-link checking website with a Vercel serverless API route. The API key is read only on the server and must never be placed in frontend JavaScript.

## Features
- Responsive neon/dark interface
- URL validation in browser and server
- VirusTotal URL reputation lookup
- Submits URLs for analysis if no cached report exists
- Explicit pending state and careful result wording
- Official Telegram and YouTube links, developer contact details

## Requirements
- GitHub account
- Vercel account
- VirusTotal API key (check VirusTotal's current terms, quotas and permitted use)

## Deploy to Vercel
1. Extract this ZIP.
2. Create a new GitHub repository named `zamin-phishhunter`.
3. Upload all files and folders from this project to the repository root. Make sure `index.html`, `api/`, `app.js`, `styles.css` and `package.json` are at the root level.
4. In Vercel, choose **Add New → Project**, import `zamin-phishhunter` from GitHub, and deploy.
5. Open the Vercel project **Settings → Environment Variables**.
6. Add variable name `VT_API_KEY` and paste your VirusTotal API key as its value. Do not add the key to `index.html`, `app.js`, GitHub, or a public file.
7. Redeploy the project after adding the variable.
8. Open your Vercel domain and test a URL. If a URL has no cached report, the site submits it and shows “Analysis submitted — result pending”. Wait a little and scan again to fetch the report.

## Run locally (optional)
Install Node.js and Vercel CLI, then run:
```bash
npm install -g vercel
vercel dev
```
Create a local `.env` file with `VT_API_KEY=your_key` before running. Never commit `.env`.

## Important limitations
- VirusTotal is a threat-intelligence aggregator, not a guarantee of safety.
- A clean report does not prove a website is safe. New or targeted phishing pages may not yet be detected.
- Free API plans have usage limits and terms. Check the provider's current policy before public launch.
- This starter currently implements the URL scanner. The decorative feature cards are roadmap descriptions, not implemented standalone IP/DNS/WHOIS/SSL tools.
- Do not scan private/internal network URLs or submit confidential links. URLs submitted to a third-party scanning service may be shared with its security community under that provider's policies.
- This is a security-awareness tool, not a substitute for professional incident response.
