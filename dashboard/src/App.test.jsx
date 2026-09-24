import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    vi
} from "vitest";

import {
    cleanup,
    render,
    screen,
    waitFor
} from "@testing-library/react";

import userEvent from
    "@testing-library/user-event";

import App from "./App";

import {
    fetchDashboardData,
    fetchIncident
} from "./api";


vi.mock(
    "./api",
    () => ({
        API_BASE_URL:
            "http://127.0.0.1:8000",
        fetchDashboardData: vi.fn(),
        fetchIncident: vi.fn()
    })
);


const dashboardData = {
    statistics: {
        events: 72,
        alerts: 7,
        incidents: 4,
        analyses: 7,
        decisions: 7,
        responses: 7,
        audit_records: 7
    },
    events: [],
    alerts: [],
    incidents: [],
    analyses: [],
    decisions: [],
    responses: [],
    auditRecords: []
};


describe(
    "App",
    () => {

        beforeEach(
            () => {

                fetchDashboardData
                    .mockResolvedValue(
                        dashboardData
                    );

                fetchIncident
                    .mockResolvedValue({});
            }
        );

        afterEach(
            () => {

                cleanup();
                vi.clearAllMocks();
            }
        );

        it(
            "loads data when the dashboard opens",
            async () => {

                render(<App />);

                await waitFor(
                    () => {

                        expect(
                            fetchDashboardData
                        ).toHaveBeenCalledTimes(1);
                    }
                );

                expect(
                    screen.getByText("72")
                ).toBeInTheDocument();
            }
        );

        it(
            "shows backend errors to the user",
            async () => {

                fetchDashboardData
                    .mockRejectedValue(
                        new Error(
                            "Backend unavailable"
                        )
                    );

                render(<App />);

                const errorMessages =
                    await screen.findAllByText(
                        "Backend unavailable"
                    );

                expect(errorMessages)
                    .toHaveLength(2);
            }
        );

        it(
            "allows navigation to incidents",
            async () => {

                const user =
                    userEvent.setup();

                render(<App />);

                await waitFor(
                    () => {

                        expect(
                            fetchDashboardData
                        ).toHaveBeenCalled();
                    }
                );

                await user.click(
                    screen.getByRole(
                        "button",
                        {
                            name: /incidents/i
                        }
                    )
                );

                expect(
                    screen.getByPlaceholderText(
                        /search incidents/i
                    )
                ).toBeInTheDocument();
            }
        );
    }
);