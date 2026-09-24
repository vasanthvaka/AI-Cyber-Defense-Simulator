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


export {
    API_BASE_URL
};