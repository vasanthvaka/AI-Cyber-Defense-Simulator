const API_BASE_URL =
    import.meta.env.VITE_API_URL
    || "http://127.0.0.1:8000";


async function request(
    endpoint,
    options = {}
) {

    const response = await fetch(
        `${API_BASE_URL}${endpoint}`,
        {
            headers: {
                Accept: "application/json"
            },
            ...options
        }
    );

    if (!response.ok) {

        let message = (
            `Request failed with status `
            + `${response.status}`
        );

        try {

            const errorData =
                await response.json();

            if (errorData.detail) {
                message = errorData.detail;
            }

        } catch {
            // Use the original error message.
        }

        throw new Error(message);
    }

    return response.json();
}


export async function fetchDashboardData(
    signal
) {

    const [
        statistics,
        events,
        alerts,
        incidents,
        analyses,
        decisions,
        responses,
        auditRecords
    ] = await Promise.all([
        request(
            "/api/statistics",
            { signal }
        ),
        request(
            "/api/events?limit=50",
            { signal }
        ),
        request(
            "/api/alerts?limit=50",
            { signal }
        ),
        request(
            "/api/incidents?limit=50",
            { signal }
        ),
        request(
            "/api/analyses?limit=50",
            { signal }
        ),
        request(
            "/api/decisions?limit=50",
            { signal }
        ),
        request(
            "/api/responses?limit=50",
            { signal }
        ),
        request(
            "/api/audit-records?limit=50",
            { signal }
        )
    ]);

    return {
        statistics: statistics.counts,
        events: events.items,
        alerts: alerts.items,
        incidents: incidents.items,
        analyses: analyses.items,
        decisions: decisions.items,
        responses: responses.items,
        auditRecords: auditRecords.items
    };
}


export async function fetchIncident(
    incidentId,
    signal
) {

    return request(
        `/api/incidents/${incidentId}`,
        { signal }
    );
}

export async function fetchSimulationStatus(signal) {
    return request(
        "/api/simulation/status",
        { signal }
    );
}


export async function generateNormalTraffic(count = 10) {
    return request(
        "/api/simulation/normal",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ count })
        }
    );
}


export async function injectAttack(attackType) {
    return request(
        `/api/simulation/attacks/${attackType}`,
        {
            method: "POST"
        }
    );
}


export async function injectRandomAttack() {
    return request(
        "/api/simulation/attacks/random",
        {
            method: "POST"
        }
    );
}


export async function explainIncident(incidentId) {
    return request(
        `/api/incidents/${incidentId}/explain`,
        {
            method: "POST"
        }
    );
}


export async function runDemoSimulation(seed = 42) {
    return request(
        "/api/simulation/demo",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ seed })
        }
    );
}


export async function startLiveSimulation(seed = null, useRandomSeed = false) {
    return request(
        "/api/simulation/live/start",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                seed: seed ? Number(seed) : null,
                use_random_seed: useRandomSeed
            })
        }
    );
}


export async function stopLiveSimulation() {
    return request(
        "/api/simulation/live/stop",
        {
            method: "POST"
        }
    );
}

export async function fetchLiveLog() {
    return request("/api/simulation/live/log");
}

export async function resetDatabase() {
    return request(
        "/api/simulation/reset",
        {
            method: "POST"
        }
    );
}

export {
    API_BASE_URL
};