import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { useAuth } from './AuthContext';
import { showToast } from './AuthContext';

const ScanJobsContext = createContext(null);

const POLL_INTERVAL_MS = 5000; // 5s instead of 3s

export const ScanJobsProvider = ({ children }) => {
    const { user } = useAuth();
    const [jobs, setJobs] = useState([]);
    const notifiedRef  = useRef(new Set());
    const timerRef     = useRef(null);
    const failCountRef = useRef(0); // consecutive failures

    const fetchJobs = useCallback(async () => {
        // Don't poll if no user or tab is hidden
        if (!user || document.hidden) return;
        try {
            const { data } = await axios.get('/api/scan/jobs');
            failCountRef.current = 0; // reset on success
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
        } catch (err) {
            const status = err?.response?.status;
            // Stop polling silently on 401 (session ended) or 429 (rate limited)
            if (status === 401 || status === 429) {
                clearInterval(timerRef.current);
                timerRef.current = null;
                return;
            }
            // Exponential backoff: stop polling after 5 consecutive failures
            failCountRef.current += 1;
            if (failCountRef.current >= 5) {
                clearInterval(timerRef.current);
                timerRef.current = null;
            }
        }
    }, [user]);

    useEffect(() => {
        if (!user) { setJobs([]); clearInterval(timerRef.current); return; }

        // Request browser notification permission once
        if (Notification?.permission === 'default') {
            Notification.requestPermission().catch(() => {});
        }

        failCountRef.current = 0;
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

    const dismissJob = useCallback(async (jobId) => {
        await axios.delete(`/api/scan/job/${jobId}/dismiss`);
        setJobs(prev => prev.filter(j => j.job_id !== jobId));
    }, []);

    const clearErrors = useCallback(async () => {
        await axios.delete('/api/scan/jobs/errors');
        setJobs(prev => prev.filter(j => j.status !== 'error'));
    }, []);

    const activeCount = jobs.filter(j => j.status === 'queued' || j.status === 'running').length;
    const errorCount  = jobs.filter(j => j.status === 'error').length;

    return (
        <ScanJobsContext.Provider value={{ jobs, activeCount, errorCount, startJob, pollJob, fetchJobs, dismissJob, clearErrors }}>
            {children}
        </ScanJobsContext.Provider>
    );
};

export const useScanJobs = () => {
    const ctx = useContext(ScanJobsContext);
    if (!ctx) throw new Error('useScanJobs must be used within ScanJobsProvider');
    return ctx;
};
