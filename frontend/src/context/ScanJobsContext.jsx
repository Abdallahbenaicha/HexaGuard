import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { useAuth } from './AuthContext';
import { showToast } from './AuthContext';

const ScanJobsContext = createContext(null);

const POLL_INTERVAL_MS = 3000;

export const ScanJobsProvider = ({ children }) => {
    const { user } = useAuth();
    const [jobs, setJobs] = useState([]);
    const notifiedRef = useRef(new Set());
    const timerRef   = useRef(null);

    const fetchJobs = useCallback(async () => {
        if (!user) return;
        try {
            const { data } = await axios.get('/api/scan/jobs');
            setJobs(Array.isArray(data) ? data : []);

            // Fire toast + browser notification for newly-done jobs
            for (const job of data) {
                if (job.status === 'done' && !notifiedRef.current.has(job.job_id)) {
                    notifiedRef.current.add(job.job_id);
                    showToast(`Scan complete: ${job.scan_type} → ${job.target}`, 'success');
                    if (Notification?.permission === 'granted') {
                        new Notification('HexaGuard — Scan Complete', {
                            body: `${job.scan_type.toUpperCase()} scan of ${job.target} finished.`,
                            icon: '/favicon.ico',
                        });
                    }
                }
                if (job.status === 'error' && !notifiedRef.current.has(job.job_id + '_err')) {
                    notifiedRef.current.add(job.job_id + '_err');
                    showToast(`Scan failed: ${job.scan_type} → ${job.message}`, 'error');
                }
            }
        } catch {
            /* network hiccup — skip silently */
        }
    }, [user]);

    useEffect(() => {
        if (!user) { setJobs([]); return; }

        // Request browser notification permission once
        if (Notification?.permission === 'default') {
            Notification.requestPermission().catch(() => {});
        }

        fetchJobs();
        timerRef.current = setInterval(fetchJobs, POLL_INTERVAL_MS);
        return () => clearInterval(timerRef.current);
    }, [user, fetchJobs]);

    const startJob = useCallback(async (endpoint, payload) => {
        const { data } = await axios.post(endpoint, payload);
        await fetchJobs();
        return data; // { job_id, status }
    }, [fetchJobs]);

    const pollJob = useCallback(async (jobId) => {
        const { data } = await axios.get(`/api/scan/job/${jobId}`);
        return data;
    }, []);

    const activeCount = jobs.filter(j => j.status === 'queued' || j.status === 'running').length;

    return (
        <ScanJobsContext.Provider value={{ jobs, activeCount, startJob, pollJob, fetchJobs }}>
            {children}
        </ScanJobsContext.Provider>
    );
};

export const useScanJobs = () => {
    const ctx = useContext(ScanJobsContext);
    if (!ctx) throw new Error('useScanJobs must be used within ScanJobsProvider');
    return ctx;
};
