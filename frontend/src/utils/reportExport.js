const BACKEND = import.meta.env.VITE_API_BASE_URL || '';

/** Build download URLs scoped to a specific scan report token. */
export function reportDownloadUrl(endpoint, token, extra = {}) {
    const params = new URLSearchParams();
    if (token) params.set('token', token);
    Object.entries(extra).forEach(([k, v]) => {
        if (v != null && v !== '') params.set(k, v);
    });
    const qs = params.toString();
    const url = `${BACKEND}${endpoint}`;
    return qs ? `${url}?${qs}` : url;
}

export const REPORT_ENDPOINTS = {
    pdf:  '/download_report',
    md:   '/download_report_md',
    csv:  '/download_report_csv',
    json: '/download_report_json',
};
