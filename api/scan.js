// Vercel serverless function. Keep VT_API_KEY in Vercel Environment Variables.
module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed." });
  }

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) return res.status(503).json({ error: "Threat scanning is not configured yet. Add VT_API_KEY in Vercel project settings." });

  const submitted = req.body && req.body.url;
  if (typeof submitted !== "string" || submitted.length > 2048) {
    return res.status(400).json({ error: "Please provide a valid URL." });
  }

  let parsed;
  try {
    parsed = new URL(submitted);
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) {
      throw new Error("Unsupported URL.");
    }
  } catch {
    return res.status(400).json({ error: "Only valid HTTP or HTTPS URLs are supported." });
  }

  // URL identifier used by VirusTotal: URL-safe base64 without trailing '='.
  const urlId = Buffer.from(parsed.href).toString("base64").replace(/=/g, "");
  const headers = { "x-apikey": apiKey, "accept": "application/json" };

  try {
    let reportResponse = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, { headers });
    if (reportResponse.ok) {
      const report = await reportResponse.json();
      const attrs = report.data && report.data.attributes;
      if (attrs && attrs.last_analysis_stats) {
        return res.status(200).json({
          status: "complete",
          stats: attrs.last_analysis_stats,
          permalink: `https://www.virustotal.com/gui/url/${urlId}`
        });
      }
    } else if (reportResponse.status !== 404) {
      const detail = await safeError(reportResponse);
      return res.status(reportResponse.status === 429 ? 429 : 502).json({ error: detail || "Threat-intelligence provider error." });
    }

    // No cached report: submit the URL for analysis. It may take time to complete.
    const body = new URLSearchParams({ url: parsed.href });
    const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { ...headers, "content-type": "application/x-www-form-urlencoded" },
      body
    });
    if (!submitResponse.ok) {
      const detail = await safeError(submitResponse);
      return res.status(submitResponse.status === 429 ? 429 : 502).json({ error: detail || "Could not submit URL for analysis." });
    }
    return res.status(200).json({ status: "pending" });
  } catch {
    return res.status(502).json({ error: "Could not connect to the threat-intelligence provider." });
  }
};

async function safeError(response) {
  try {
    const data = await response.json();
    return data.error && data.error.message ? data.error.message : "";
  } catch {
    return "";
  }
}
