export function renderPairingFlowSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 300" role="img" aria-label="Agent Huddle pairing flow">
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#4a626b"></path>
    </marker>
  </defs>
  <rect x="12" y="12" width="616" height="276" rx="14" fill="#fffdf8" stroke="#d9cec0"></rect>

  <rect x="26" y="34" width="136" height="52" rx="10" fill="#f8efe1" stroke="#d8ccbc"></rect>
  <text x="94" y="55" text-anchor="middle" font-size="13" fill="#243138" font-family="Plus Jakarta Sans, sans-serif">1. /login</text>
  <text x="94" y="72" text-anchor="middle" font-size="11" fill="#5a686d" font-family="Plus Jakarta Sans, sans-serif">Google auth</text>

  <rect x="198" y="34" width="152" height="52" rx="10" fill="#f8efe1" stroke="#d8ccbc"></rect>
  <text x="274" y="55" text-anchor="middle" font-size="13" fill="#243138" font-family="Plus Jakarta Sans, sans-serif">2. /pair</text>
  <text x="274" y="72" text-anchor="middle" font-size="11" fill="#5a686d" font-family="Plus Jakarta Sans, sans-serif">Issue one-time code</text>

  <rect x="386" y="34" width="228" height="52" rx="10" fill="#eaf4f2" stroke="#bfded8"></rect>
  <text x="500" y="55" text-anchor="middle" font-size="13" fill="#1f4f4a" font-family="Plus Jakarta Sans, sans-serif">3. MCP pair_with_code</text>
  <text x="500" y="72" text-anchor="middle" font-size="11" fill="#4e666e" font-family="Plus Jakarta Sans, sans-serif">same code on both machines</text>

  <line x1="162" y1="60" x2="198" y2="60" stroke="#4a626b" stroke-width="2" marker-end="url(#arrow)"></line>
  <line x1="350" y1="60" x2="386" y2="60" stroke="#4a626b" stroke-width="2" marker-end="url(#arrow)"></line>

  <rect x="48" y="172" width="164" height="68" rx="12" fill="#fff" stroke="#d7c8b5"></rect>
  <text x="130" y="198" text-anchor="middle" font-size="13" fill="#243138" font-family="Plus Jakarta Sans, sans-serif">Machine A</text>
  <text x="130" y="216" text-anchor="middle" font-size="11" fill="#5a686d" font-family="Plus Jakarta Sans, sans-serif">MCP client</text>

  <rect x="428" y="172" width="164" height="68" rx="12" fill="#fff" stroke="#d7c8b5"></rect>
  <text x="510" y="198" text-anchor="middle" font-size="13" fill="#243138" font-family="Plus Jakarta Sans, sans-serif">Machine B</text>
  <text x="510" y="216" text-anchor="middle" font-size="11" fill="#5a686d" font-family="Plus Jakarta Sans, sans-serif">MCP client</text>

  <rect x="240" y="160" width="160" height="40" rx="10" fill="#edf5fc" stroke="#c3d9ef"></rect>
  <text x="320" y="184" text-anchor="middle" font-size="12" fill="#2b4f70" font-family="Plus Jakarta Sans, sans-serif">Hosted Signaling</text>

  <rect x="240" y="214" width="160" height="40" rx="10" fill="#fef2ea" stroke="#f2d1bb"></rect>
  <text x="320" y="238" text-anchor="middle" font-size="12" fill="#74432f" font-family="Plus Jakarta Sans, sans-serif">TURN Fallback</text>

  <line x1="212" y1="204" x2="240" y2="181" stroke="#4a626b" stroke-width="2" marker-end="url(#arrow)"></line>
  <line x1="428" y1="204" x2="400" y2="181" stroke="#4a626b" stroke-width="2" marker-end="url(#arrow)"></line>
  <line x1="240" y1="234" x2="212" y2="206" stroke="#b06c50" stroke-width="2" marker-end="url(#arrow)"></line>
  <line x1="400" y1="234" x2="428" y2="206" stroke="#b06c50" stroke-width="2" marker-end="url(#arrow)"></line>
</svg>`;
}
