const campaignData = [
  {
    name: "Cyber Awareness Week",
    start: "2025-06-01",
    end: "2025-06-05",
    status: "Ongoing",
    clickThroughRate: "28%",
    targets: [
      { email: "hr@example.com", clicked: true, clickDate: "2025-06-02", clickTime: "09:35 AM" },
      { email: "admin@example.com", clicked: false }
    ]
  },
  {
    name: "Finance Test Run",
    start: "2025-05-15",
    end: "2025-05-20",
    status: "Completed",
    clickThroughRate: "18%",
    targets: [
      { email: "finance@example.com", clicked: false },
      { email: "accounting@example.com", clicked: true, clickDate: "2025-05-17", clickTime: "11:15 AM" }
    ]
  }
];

function renderCampaigns(data) {
  const campaignList = document.getElementById("campaignList");
  campaignList.innerHTML = "";

  if (data.length === 0) {
    campaignList.innerHTML = "<p>No campaigns match the filters.</p>";
    return;
  }

  data.forEach((campaign, index) => {
    const card = document.createElement("div");
    card.className = "campaign-card";
    card.innerHTML = `
      <div class="campaign-header" onclick="toggleDetails('details-${index}')">
        <h3>${campaign.name}</h3>
        <span class="status ${campaign.status.toLowerCase()}">${campaign.status}</span>
      </div>
      <div class="campaign-details" id="details-${index}">
        <p><strong>Start:</strong> ${campaign.start}</p>
        <p><strong>End:</strong> ${campaign.end}</p>
        <p><strong>Click-through rate:</strong> ${campaign.clickThroughRate}</p>
        <p><strong>Targets:</strong></p>
        <ol>
          ${campaign.targets.map(t => `
            <li>${t.email} - ${t.clicked ? `Clicked at ${t.clickTime} on ${t.clickDate}` : "Not Clicked"}</li>
          `).join('')}
        </ol>
        <button onclick="alert('Generate report for ${campaign.name}')">View Report</button>
        <button onclick="alert('Deleting ${campaign.name}')">Delete</button>
      </div>
    `;
    campaignList.appendChild(card);
  });
}

function toggleDetails(id) {
  const el = document.getElementById(id);
  el.style.display = el.style.display === "none" ? "block" : "none";
}

function filterCampaigns() {
  const keyword = document.getElementById("keywordInput").value.toLowerCase();
  const startDate = document.getElementById("startDateInput").value;
  const endDate = document.getElementById("endDateInput").value;
  const status = document.getElementById("statusInput").value;
  const minTargets = parseInt(document.getElementById("minTargetsInput").value, 10) || 0;

  const filtered = campaignData.filter(campaign => {
    const matchesKeyword =
      campaign.name.toLowerCase().includes(keyword) ||
      campaign.targets.some(t => t.email.toLowerCase().includes(keyword));

    const matchesStart = !startDate || campaign.start >= startDate;
    const matchesEnd = !endDate || campaign.end <= endDate;
    const matchesStatus = !status || campaign.status === status;
    const matchesTargetCount = campaign.targets.length >= minTargets;

    return matchesKeyword && matchesStart && matchesEnd && matchesStatus && matchesTargetCount;
  });

  renderCampaigns(filtered);
}

function resetFilters() {
  document.getElementById("keywordInput").value = "";
  document.getElementById("startDateInput").value = "";
  document.getElementById("endDateInput").value = "";
  document.getElementById("statusInput").value = "";
  document.getElementById("minTargetsInput").value = "";

  renderCampaigns(campaignData);
}

renderCampaigns(campaignData);
