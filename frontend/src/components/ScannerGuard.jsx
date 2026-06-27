import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

/**
 * Wraps a scanner page. If the user does not have access to `slug`,
 * redirects to the Scanner Hub with a blocked=1 flag so the hub can
 * display an explanatory banner.
 *
 * Access rules:
 *   admin                   → always allowed
 *   allowed_scanners = null → unrestricted (legacy / no restriction set)
 *   allowed_scanners = [...] → only if slug is in the list
 */
export default function ScannerGuard({ slug, element }) {
    const { user } = useAuth();

    if (!user) return null; // AuthProvider handles unauthenticated redirect

    if (user.role === 'admin') return element;

    const allowed = user.allowed_scanners ?? null;
    if (allowed === null) return element;           // unrestricted

    if (allowed.includes(slug)) return element;

    return <Navigate to={`/scan?blocked=${slug}`} replace />;
}
