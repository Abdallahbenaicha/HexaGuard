import React, { useState, useEffect, useCallback } from "react";
import axios from "axios";
import { Link } from "react-router-dom";

/* ── Icons ──────────────────────────────────────────────────────────────── */
const ICONS = {
  target: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="6" />
      <circle cx="12" cy="12" r="2" />
    </svg>
  ),
  shield: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  award: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="8" r="6" />
      <path d="M15.477 12.89L17 22l-5-3-5 3 1.523-9.11" />
    </svg>
  ),
};

const TIER_COLORS = {
  Apprentice:   { bg: "rgba(0,180,216,0.12)", border: "#00b4d8", text: "#00b4d8" },
  Practitioner: { bg: "rgba(255,107,53,0.12)",  border: "#ff6b35", text: "#ff6b35" },
  Expert:       { bg: "rgba(123,45,139,0.12)",  border: "#7b2d8b", text: "#c084fc" },
};

/* ── Progress ring (SVG) ─────────────────────────────────────────────────── */
function ProgressRing({ percent, color, size = 88 }) {
  const r   = (size - 10) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (percent / 100) * circ;
  return (
    <svg width={size} height={size} style={{ transform: "rotate(-90deg)", flexShrink: 0 }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1e293b" strokeWidth="8" />
      <circle
        cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={color} strokeWidth="8"
        strokeDasharray={circ} strokeDashoffset={offset}
        strokeLinecap="round"
        style={{ transition: "stroke-dashoffset 0.8s ease" }}
      />
      <text
        x={size / 2} y={size / 2 + 6}
        textAnchor="middle"
        style={{
          transform: `rotate(90deg) translate(0, 0)`,
          transformOrigin: `${size / 2}px ${size / 2}px`,
          fill: "#f1f5f9", fontSize: "15px", fontWeight: 700,
        }}
      >
        {percent}%
      </text>
    </svg>
  );
}

/* ── Track Detail Modal ───────────────────────────────────────────────────── */
function TrackModal({ track, onClose }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get(`/api/tracks/${track.id}`, { withCredentials: true })
      .then(r => setDetail(r.data))
      .catch(() => setDetail(null))
      .finally(() => setLoading(false));
  }, [track.id]);

  const tier = TIER_COLORS[track.tier] || TIER_COLORS.Apprentice;

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 1000,
        background: "rgba(0,0,0,0.75)", backdropFilter: "blur(4px)",
        display: "flex", alignItems: "center", justifyContent: "center",
        padding: "1rem",
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: "#0f172a", border: `1.5px solid ${track.color}55`,
          borderRadius: "1rem", maxWidth: "600px", width: "100%",
          maxHeight: "85vh", overflowY: "auto", padding: "1.75rem",
          boxShadow: `0 20px 60px ${track.color}22`,
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Modal header */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.25rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <div style={{
              width: 36, height: 36, borderRadius: "0.5rem",
              background: `${track.color}22`, display: "flex",
              alignItems: "center", justifyContent: "center", color: track.color,
            }}>
              <div style={{ width: 20, height: 20 }}>{ICONS[track.icon]}</div>
            </div>
            <div>
              <h3 style={{ margin: 0, color: "#f1f5f9", fontSize: "1.1rem", fontWeight: 700 }}>
                {track.name_ar}
              </h3>
              <span style={{
                fontSize: "0.7rem", padding: "2px 8px", borderRadius: "1rem",
                background: tier.bg, border: `1px solid ${tier.border}`, color: tier.text,
              }}>
                {track.tier}
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent", border: "none", color: "#64748b",
              fontSize: "1.4rem", cursor: "pointer", padding: "0.25rem",
            }}
          >
            ✕
          </button>
        </div>

        {/* Progress summary banner */}
        <div style={{
          background: "#1e293b", borderRadius: "0.75rem", padding: "1rem",
          marginBottom: "1.25rem", display: "flex", alignItems: "center",
          justifyContent: "space-around", textAlign: "center",
        }}>
          <div>
            <div style={{ fontSize: "1.4rem", fontWeight: 800, color: track.color }}>
              {track.progress.percent}%
            </div>
            <div style={{ fontSize: "0.72rem", color: "#64748b" }}>الإنجاز الإجمالي</div>
          </div>
          <div style={{ width: 1, height: 36, background: "#334155" }} />
          <div>
            <div style={{ fontSize: "1.4rem", fontWeight: 800, color: "#f1f5f9" }}>
              {track.progress.practiced?.length || 0}
            </div>
            <div style={{ fontSize: "0.72rem", color: "#64748b" }}>أنواع ممارَسة</div>
          </div>
          <div style={{ width: 1, height: 36, background: "#334155" }} />
          <div>
            <div style={{ fontSize: "1.4rem", fontWeight: 800, color: "#f59e0b" }}>
              {track.progress.dojo_streak} 🔥
            </div>
            <div style={{ fontSize: "0.72rem", color: "#64748b" }}>Streak الدوجو</div>
          </div>
        </div>

        {/* Action Button for SOC Analyst */}
        {track.id === "soc-analyst" && (
          <Link
            to="/casefiles"
            style={{
              display: "flex", alignItems: "center", justifyContent: "center", gap: "0.5rem",
              marginBottom: "1.25rem", width: "100%", padding: "0.85rem",
              background: "linear-gradient(90deg, #00b4d8, #0077b6)", color: "#ffffff",
              borderRadius: "0.75rem", textDecoration: "none", fontWeight: 700, fontSize: "0.9rem",
              boxShadow: "0 4px 15px rgba(0,180,216,0.3)"
            }}
          >
            🛡️ فتح معمل ملفات قضايا SOC (Forensic Case Files) →
          </Link>
        )}

        {/* Steps list */}
        {loading ? (
          <div style={{ color: "#64748b", textAlign: "center", padding: "1.5rem" }}>
            جاري تحميل الخطوات...
          </div>
        ) : detail?.steps ? (
          <>
            <div style={{ color: "#94a3b8", fontSize: "0.78rem", fontWeight: 600, marginBottom: "0.5rem" }}>
              المهارات المطلوبة للمسار ({detail.steps.length}):
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
              {detail.steps.map(step => (
                <div
                  key={step.vuln_type}
                  style={{
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                    background: step.practiced ? "rgba(16,185,129,0.06)" : "#1e293b",
                    border: `1px solid ${step.practiced ? "rgba(16,185,129,0.3)" : "#334155"}`,
                    borderRadius: "0.5rem", padding: "0.6rem 0.85rem",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                    <span>{step.practiced ? "✅" : "⏳"}</span>
                    <span style={{
                      color: step.practiced ? "#f1f5f9" : "#64748b",
                      fontSize: "0.82rem", fontFamily: "monospace",
                    }}>
                      {step.vuln_type}
                    </span>
                  </div>
                  {step.practiced_count > 0 && (
                    <span style={{ color: "#64748b", fontSize: "0.72rem" }}>×{step.practiced_count}</span>
                  )}
                  <Link
                    to={`/learn/vulnerabilities?type=${step.vuln_type}`}
                    style={{ color: track.color, fontSize: "0.72rem", textDecoration: "none" }}
                  >
                    تعلّم →
                  </Link>
                </div>
              ))}
            </div>
          </>
        ) : null}

        <button
          onClick={onClose}
          style={{
            marginTop: "1.5rem", width: "100%", padding: "0.7rem",
            background: "transparent", border: `1px solid #334155`,
            borderRadius: "0.6rem", color: "#94a3b8", cursor: "pointer",
            fontSize: "0.88rem",
          }}
        >
          إغلاق
        </button>
      </div>
    </div>
  );
}

/* ── Main Page ───────────────────────────────────────────────────────────── */
export default function TracksPage() {
  const [tracks, setTracks]         = useState([]);
  const [certReadiness, setCertReadiness] = useState([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [selected, setSelected]     = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      axios.get("/api/tracks", { withCredentials: true }),
      axios.get("/api/tracks/cert-readiness", { withCredentials: true }),
    ])
      .then(([tracksRes, certRes]) => {
        setTracks(tracksRes.data.tracks || []);
        setCertReadiness(certRes.data.certifications || []);
      })
      .catch(e => setError(e.response?.data?.error || "فشل تحميل المسارات"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div style={{
      minHeight: "100vh", background: "#0a0f1e",
      padding: "2rem 1.5rem", maxWidth: "1100px", margin: "0 auto",
    }}>
      {/* Page header */}
      <div style={{ marginBottom: "2.5rem" }}>
        <h1 style={{
          margin: 0, fontSize: "clamp(1.6rem, 3vw, 2.2rem)",
          fontWeight: 800, color: "#f1f5f9",
          background: "linear-gradient(135deg, #60a5fa, #a78bfa)",
          WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
        }}>
          🗺️ مسارات التعلم وبوصلة المهارات (Learning Compass)
        </h1>
        <p style={{ color: "#64748b", marginTop: "0.5rem", fontSize: "0.95rem" }}>
          مسارات موجَّهة تجمع ميزات المنصة في رحلة واحدة بهدف معلَن — مبنية على بياناتك الفعلية من Skill Ledger والدوجو وملفات قضايا SOC.
        </p>
      </div>

      {loading && (
        <div style={{ color: "#60a5fa", textAlign: "center", paddingTop: "3rem", fontSize: "1rem" }}>
          ⏳ جاري تحميل مسارات التعلم...
        </div>
      )}

      {error && (
        <div style={{
          background: "rgba(239,68,68,0.1)", border: "1px solid #ef4444",
          borderRadius: "0.75rem", padding: "1rem", color: "#ef4444",
          textAlign: "center", marginBottom: "2rem",
        }}>
          {error}
        </div>
      )}

      {/* Track cards grid */}
      {!loading && !error && (
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
          gap: "1.5rem",
          marginBottom: "3rem",
        }}>
          {tracks.map(track => {
            const tier = TIER_COLORS[track.tier] || TIER_COLORS.Apprentice;
            return (
              <div
                key={track.id}
                id={`track-card-${track.id}`}
                onClick={() => setSelected(track)}
                style={{
                  background: "linear-gradient(145deg, #0f172a, #1e293b)",
                  border: `1.5px solid ${track.color}33`,
                  borderRadius: "1.25rem", padding: "1.75rem",
                  cursor: "pointer", transition: "all 0.25s ease",
                  position: "relative", overflow: "hidden",
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.borderColor = track.color + "88";
                  e.currentTarget.style.transform = "translateY(-3px)";
                  e.currentTarget.style.boxShadow = `0 12px 40px ${track.color}22`;
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.borderColor = track.color + "33";
                  e.currentTarget.style.transform = "translateY(0)";
                  e.currentTarget.style.boxShadow = "none";
                }}
              >
                {/* Background glow */}
                <div style={{
                  position: "absolute", top: -20, right: -20,
                  width: 100, height: 100, borderRadius: "50%",
                  background: `radial-gradient(circle, ${track.color}18 0%, transparent 70%)`,
                  pointerEvents: "none",
                }} />

                {/* Top row: icon + tier badge + ring */}
                <div style={{ display: "flex", alignItems: "flex-start", gap: "1rem", marginBottom: "1.25rem" }}>
                  <div style={{
                    width: 48, height: 48, borderRadius: "0.75rem",
                    background: `${track.color}22`, border: `1.5px solid ${track.color}44`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    color: track.color, flexShrink: 0,
                  }}>
                    <div style={{ width: 26, height: 26 }}>{ICONS[track.icon]}</div>
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <h2 style={{
                      margin: 0, color: "#f1f5f9", fontSize: "1rem",
                      fontWeight: 700, lineHeight: 1.3,
                    }}>{track.name_ar}</h2>
                    <span style={{
                      display: "inline-block", marginTop: 5,
                      fontSize: "0.68rem", padding: "2px 10px", borderRadius: "1rem",
                      background: tier.bg, border: `1px solid ${tier.border}`,
                      color: tier.text, letterSpacing: "0.05em",
                    }}>{track.tier}</span>
                  </div>
                  <ProgressRing percent={track.progress.percent} color={track.color} size={80} />
                </div>

                {/* Description */}
                <p style={{
                  color: "#94a3b8", fontSize: "0.82rem", lineHeight: 1.65,
                  margin: 0, marginBottom: "1.25rem",
                  display: "-webkit-box", WebkitLineClamp: 3,
                  WebkitBoxOrient: "vertical", overflow: "hidden",
                }}>
                  {track.description_ar}
                </p>

                {/* Footer stats */}
                <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                  <div style={{
                    background: "#0a0f1e", borderRadius: "0.5rem",
                    padding: "0.35rem 0.75rem", border: "1px solid #334155",
                    fontSize: "0.72rem", color: "#64748b",
                  }}>
                    🎯 {track.progress.practiced?.length || 0}/{(track.progress.practiced?.length || 0) + (track.progress.missing?.length || 0)} نوع
                  </div>
                  <div style={{
                    background: "#0a0f1e", borderRadius: "0.5rem",
                    padding: "0.35rem 0.75rem", border: "1px solid #334155",
                    fontSize: "0.72rem", color: "#64748b",
                  }}>
                    🔥 {track.progress.dojo_streak} يوم streak
                  </div>
                  {track.id === "soc-analyst" && (
                    <div style={{
                      background: "rgba(0,180,216,0.1)", borderRadius: "0.5rem",
                      padding: "0.35rem 0.75rem", border: "1px solid #00b4d844",
                      fontSize: "0.72rem", color: "#00b4d8",
                    }}>
                      📁 قضايا SOC
                    </div>
                  )}
                  {track.cert_disclaimer && (
                    <div style={{
                      background: "rgba(251,191,36,0.08)", borderRadius: "0.5rem",
                      padding: "0.35rem 0.75rem", border: "1px solid #fbbf2444",
                      fontSize: "0.72rem", color: "#fbbf24",
                    }}>
                      📋 eJPT / OSCP
                    </div>
                  )}
                </div>

                {/* Progress bar */}
                <div style={{
                  marginTop: "1rem", height: 5, borderRadius: "3px",
                  background: "#1e293b", overflow: "hidden",
                }}>
                  <div style={{
                    height: "100%", width: `${track.progress.percent}%`,
                    background: `linear-gradient(90deg, ${track.color}99, ${track.color})`,
                    borderRadius: "3px", transition: "width 0.8s ease",
                  }} />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Certification Readiness Compass (E-04) */}
      {!loading && !error && certReadiness.length > 0 && (
        <div style={{
          background: "linear-gradient(145deg, #0f172a, #131d35)",
          border: "1px solid #1e293b", borderRadius: "1.5rem",
          padding: "2rem", marginTop: "2rem",
        }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
            <h2 style={{
              margin: 0, fontSize: "1.3rem", fontWeight: 700, color: "#f1f5f9",
              display: "flex", alignItems: "center", gap: "0.5rem"
            }}>
              🎯 بوصلة جاهزية الشهادات المهنية (Cert Readiness - E-04)
            </h2>
            <span style={{
              fontSize: "0.72rem", color: "#94a3b8", background: "#1e293b",
              padding: "0.25rem 0.75rem", borderRadius: "1rem",
            }}>
              حساب حي من Skill Ledger
            </span>
          </div>
          <p style={{ color: "#64748b", fontSize: "0.85rem", marginBottom: "1.5rem" }}>
            مؤشر تقديري داخلي مبني على مجالات التغطية والمهارات الممارسة في سجل المهارات الخاص بك.
          </p>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
            gap: "1.25rem",
          }}>
            {certReadiness.map((cert) => (
              <div
                key={cert.id}
                style={{
                  background: "#0a0f1e", border: `1px solid ${cert.badge_color}44`,
                  borderRadius: "1rem", padding: "1.25rem",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1rem" }}>
                  <div>
                    <span style={{
                      fontSize: "0.68rem", fontWeight: 700, color: cert.badge_color,
                      textTransform: "uppercase", letterSpacing: "0.05em",
                    }}>
                      {cert.provider}
                    </span>
                    <h3 style={{ margin: "0.2rem 0 0", color: "#f1f5f9", fontSize: "0.95rem", fontWeight: 700 }}>
                      {cert.name}
                    </h3>
                  </div>
                  <div style={{
                    fontSize: "1.2rem", fontWeight: 800, color: cert.badge_color,
                  }}>
                    {cert.readiness_pct}%
                  </div>
                </div>

                {/* Progress bar */}
                <div style={{
                  height: 6, borderRadius: 3, background: "#1e293b", overflow: "hidden", marginBottom: "1rem",
                }}>
                  <div style={{
                    height: "100%", width: `${cert.readiness_pct}%`,
                    background: cert.badge_color, borderRadius: 3,
                    transition: "width 0.8s ease",
                  }} />
                </div>

                <div style={{ fontSize: "0.75rem", color: "#94a3b8", marginBottom: "0.75rem" }}>
                  المهارات المغطاة: <strong style={{ color: "#10b981" }}>{cert.covered_skills.length}</strong> / {cert.total_skills}
                </div>

                {/* Tags */}
                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem", marginBottom: "1rem" }}>
                  {cert.covered_skills.map((s) => (
                    <span key={s} style={{
                      fontSize: "0.68rem", padding: "2px 6px", borderRadius: "0.35rem",
                      background: "rgba(16,185,129,0.1)", color: "#10b981", border: "1px solid rgba(16,185,129,0.3)",
                      fontFamily: "monospace",
                    }}>
                      ✓ {s}
                    </span>
                  ))}
                  {cert.missing_skills.slice(0, 3).map((s) => (
                    <span key={s} style={{
                      fontSize: "0.68rem", padding: "2px 6px", borderRadius: "0.35rem",
                      background: "#1e293b", color: "#64748b", border: "1px solid #334155",
                      fontFamily: "monospace",
                    }}>
                      ○ {s}
                    </span>
                  ))}
                  {cert.missing_skills.length > 3 && (
                    <span style={{ fontSize: "0.68rem", color: "#64748b", alignSelf: "center" }}>
                      +{cert.missing_skills.length - 3} أخرى
                    </span>
                  )}
                </div>

                <div style={{
                  fontSize: "0.7rem", color: "#f59e0b", background: "rgba(245,158,11,0.06)",
                  padding: "0.5rem", borderRadius: "0.5rem", border: "1px solid rgba(245,158,11,0.2)",
                  lineHeight: 1.4,
                }}>
                  ⚠️ {cert.disclaimer_ar}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detail Modal */}
      {selected && (
        <TrackModal track={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
