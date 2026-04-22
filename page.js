"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const router = useRouter();

  const [step, setStep] = useState("login"); // login | otp
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [checkedLogin, setCheckedLogin] = useState(false);

  useEffect(() => {
    const loggedIn = localStorage.getItem("loggedIn") === "true";

    if (loggedIn) {
      router.push("/analyser");
    } else {
      setCheckedLogin(true);
    }
  }, [router]);

  async function handleLogin(e) {
    e.preventDefault();
    setError("");
    setMessage("");

    if (!email.trim() || !password.trim()) {
      setError("Email and password are required.");
      return;
    }

    try {
      setLoading(true);

      const res = await fetch("http://localhost:8000/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          email,
          password
        })
      });

      const data = await res.json();

      if (data.success && data.mfa_required) {
        setStep("otp");
        setMessage(data.message || "OTP sent to your Gmail.");
      } else if (data.success) {
        // fallback in case MFA is disabled
        localStorage.setItem("loggedIn", "true");
        localStorage.setItem("userEmail", email);
        router.push("/analyser");
      } else {
        setError(data.message || "Invalid email or password.");
      }
    } catch (err) {
      console.error("Login error:", err);
      setError("Could not connect to server.");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerifyOtp(e) {
    e.preventDefault();
    setError("");
    setMessage("");

    if (!otp.trim()) {
      setError("OTP is required.");
      return;
    }

    try {
      setLoading(true);

      const res = await fetch("http://localhost:8000/api/verify-otp", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          email,
          otp
        })
      });

      const data = await res.json();

      if (data.success) {
        localStorage.setItem("loggedIn", "true");
        localStorage.setItem("userEmail", email);
        router.push("/analyser");
      } else {
        setError(data.message || "Invalid OTP.");
      }
    } catch (err) {
      console.error("OTP verify error:", err);
      setError("Could not verify OTP.");
    } finally {
      setLoading(false);
    }
  }

  if (!checkedLogin) {
    return null;
  }

  return (
    <main className="login-wrap">
      <div className="login-box">
        <h1 className="login-title">Welcome</h1>
        <p className="login-subtitle">
          Login to access the PhishShield.
        </p>

        {step === "login" ? (
          <form onSubmit={handleLogin} className="login-form">
            <label className="login-label">Email</label>
            <input
              className="login-input"
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />

            <label className="login-label">Password</label>
            <input
              className="login-input"
              type="password"
              placeholder="Enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />

            {error ? <p className="login-error">{error}</p> : null}
            {message ? <p className="login-success">{message}</p> : null}

            <button className="login-btn" type="submit" disabled={loading}>
              {loading ? "Checking..." : "Login"}
            </button>

            <button
              className="login-btn secondary"
              type="button"
              onClick={() => {
                setEmail("");
                setPassword("");
                setError("");
                setMessage("");
              }}
            >
              Clear
            </button>
          </form>
        ) : (
          <form onSubmit={handleVerifyOtp} className="login-form">
            <label className="login-label">Enter OTP</label>
            <input
              className="login-input"
              type="text"
              placeholder="Enter 6-digit OTP"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
            />

            {error ? <p className="login-error">{error}</p> : null}
            {message ? <p className="login-success">{message}</p> : null}

            <button className="login-btn" type="submit" disabled={loading}>
              {loading ? "Verifying..." : "Verify OTP"}
            </button>

            <button
              className="login-btn secondary"
              type="button"
              onClick={() => {
                setStep("login");
                setOtp("");
                setError("");
                setMessage("");
              }}
            >
              Back
            </button>
          </form>
        )}

        <div className="login-tips">
          <h3>Quick Phishing Safety Tips</h3>
          <ul>
            <li>Never share OTP or passwords via email.</li>
            <li>Check sender domain carefully.</li>
            <li>Avoid clicking shortened links.</li>
          </ul>
        </div>
      </div>
    </main>
  );
}