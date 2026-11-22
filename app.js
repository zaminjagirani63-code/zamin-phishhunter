const form = document.getElementById("scanForm");
const input = document.getElementById("urlInput");
const button = document.getElementById("scanButton");
const result = document.getElementById("result");

function showResult(kind, title, message, stats = []) {
  result.className = `result ${kind}`;
  result.innerHTML = "";
  const heading = document.createElement("h3");
  heading.textContent = title;
  const paragraph = document.createElement("p");
  paragraph.textContent = message;
  result.append(heading, paragraph);
  if (stats.length) {
    const group = document.createElement("div");
    group.className = "stats";
    stats.forEach(([label, value]) => {
      const item = document.createElement("span");
      item.className = "stat";
      item.textContent = `${label}: ${value}`;
      group.append(item);
    });
    result.append(group);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const raw = input.value.trim();
  let parsed;
  try {
    parsed = new URL(raw);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only HTTP and HTTPS URLs are supported.");
  } catch (error) {
    showResult("warn", "Please enter a valid URL", error.message || "Include https:// or http:// in the address.");
    return;
  }
  button.disabled = true;
  button.textContent = "Checking…";
  showResult("", "Checking URL", "Contacting the threat-intelligence service. This may take a few seconds.");
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: parsed.href })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The scan service could not complete the request.");
    if (data.status === "pending") {
      showResult("warn", "Analysis submitted — result pending", "The URL was not found in the current report cache, so a scan was submitted. Wait briefly and scan again to retrieve the report.");
    } else {
      const s = data.stats || {};
      const malicious = Number(s.malicious || 0);
      const suspicious = Number(s.suspicious || 0);
      const stats = [
        ["Malicious", s.malicious ?? 0],
        ["Suspicious", s.suspicious ?? 0],
        ["Harmless", s.harmless ?? 0],
        ["Undetected", s.undetected ?? 0]
      ];
      if (malicious > 0) {
        showResult("danger", "THREAT DETECTED", "One or more security engines flagged this URL as malicious. Do not enter credentials or personal information.", stats);
      } else if (suspicious > 0) {
        showResult("warn", "SUSPICIOUS SIGNALS FOUND", "Some security engines reported suspicious activity. Treat this link with caution.", stats);
      } else {
        showResult("good", "NO THREAT DETECTED IN THIS REPORT", "No malicious or suspicious detections appear in this report. This is not proof that the website is safe; newly created or targeted phishing sites may be missed.", stats);
      }
      const note = document.createElement("p");
      note.textContent = "Source: VirusTotal. Detection counts are not a guarantee. Avoid opening links you do not trust.";
      result.append(note);
    }
  } catch (error) {
    showResult("warn", "Scan unavailable", error.message + " Check that the VirusTotal API key is configured in Vercel and try again.");
  } finally {
    button.disabled = false;
    button.innerHTML = 'Analyze URL <i data-lucide="arrow-right"></i>';
    if (window.lucide) lucide.createIcons();
  }
});
