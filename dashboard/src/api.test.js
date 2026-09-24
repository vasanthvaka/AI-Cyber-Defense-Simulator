import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    vi
} from "vitest";

import {
    API_BASE_URL,
    fetchDashboardData,
    fetchIncident
} from "./api";


function createResponse(
    data,
    {
        ok = true,
        status = 200
    } = {}
) {
    return {
        ok,
        status,
        json: vi.fn().mockResolvedValue(data)
    };
}


describe(
    "dashboard API",
    () => {

        beforeEach(
            () => {
                vi.stubGlobal(
                    "fetch",
                    vi.fn()
                );
            }
        );

        afterEach(
            () => {
                vi.unstubAllGlobals();
                vi.restoreAllMocks();
            }
        );

        it(
            "loads and transforms all dashboard data",
            async () => {

                const responses = {
                    "/api/statistics": {
                        counts: {
                            events: 72,
                            alerts: 7,
                            incidents: 4,
                            analyses: 7,
                            decisions: 7,
                            responses: 7,
                            audit_records: 7
                        }
                    },
                    "/api/events?limit=50": {
                        items: [{ id: 1 }]
                    },
                    "/api/alerts?limit=50": {
                        items: [{ id: 2 }]
                    },
                    "/api/incidents?limit=50": {
                        items: [{ incident_id: "incident-1" }]
                    },
                    "/api/analyses?limit=50": {
                        items: [{ id: 4 }]
                    },
                    "/api/decisions?limit=50": {
                        items: [{ id: 5 }]
                    },
                    "/api/responses?limit=50": {
                        items: [{ id: 6 }]
                    },
                    "/api/audit-records?limit=50": {
                        items: [{ id: 7 }]
                    }
                };

                fetch.mockImplementation(
                    async (url) => {

                        const requestUrl =
                            new URL(url);

                        const endpoint =
                            requestUrl.pathname
                            + requestUrl.search;

                        return createResponse(
                            responses[endpoint]
                        );
                    }
                );

                const result =
                    await fetchDashboardData();

                expect(fetch).toHaveBeenCalledTimes(8);

                expect(result.statistics.events)
                    .toBe(72);

                expect(result.events)
                    .toEqual([{ id: 1 }]);

                expect(result.alerts)
                    .toEqual([{ id: 2 }]);

                expect(result.incidents)
                    .toEqual([
                        {
                            incident_id:
                                "incident-1"
                        }
                    ]);

                expect(result.auditRecords)
                    .toEqual([{ id: 7 }]);
            }
        );

        it(
            "uses the backend error detail",
            async () => {

                fetch.mockImplementation(
                    async (url) => {

                        if (
                            url.endsWith(
                                "/api/statistics"
                            )
                        ) {
                            return createResponse(
                                {
                                    detail:
                                        "Backend unavailable"
                                },
                                {
                                    ok: false,
                                    status: 503
                                }
                            );
                        }

                        return createResponse(
                            { items: [] }
                        );
                    }
                );

                await expect(
                    fetchDashboardData()
                ).rejects.toThrow(
                    "Backend unavailable"
                );
            }
        );

        it(
            "loads one incident by its ID",
            async () => {

                const incident = {
                    incident_id: "incident-123",
                    incident_type: "PORT_SCAN"
                };

                fetch.mockResolvedValue(
                    createResponse(incident)
                );

                const result =
                    await fetchIncident(
                        "incident-123"
                    );

                expect(fetch)
                    .toHaveBeenCalledWith(
                        `${API_BASE_URL}`
                        + "/api/incidents/"
                        + "incident-123",
                        expect.objectContaining({
                            signal: undefined
                        })
                    );

                expect(result).toEqual(incident);
            }
        );
    }
);