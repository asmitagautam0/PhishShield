"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

export default function NavBar() {
  const pathname = usePathname();
  const router = useRouter();
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    const loggedIn = localStorage.getItem("loggedIn") === "true";
    setIsLoggedIn(loggedIn);
  }, [pathname]);

  const isActive = (href) => pathname === href;

  function handleLogout() {
    localStorage.removeItem("loggedIn");
    localStorage.removeItem("userEmail");

    // redirect to login page
    router.push("/");
  }

  return (
    <nav className="navbar">
      <div className="nav-inner">
        <div className="brand">PhishShield</div>

        <div className="nav-links">
          {!isLoggedIn ? (
            <Link className={isActive("/") ? "active" : ""} href="/">
              Login
            </Link>
          ) : (
            <>
              <Link className={isActive("/analyser") ? "active" : ""} href="/analyser">
                Analyser
              </Link>

              <Link className={isActive("/logs") ? "active" : ""} href="/logs">
                Logs
              </Link>

              {/* Logout Button */}
              <button
                onClick={handleLogout}
                style={{
                  backgroundColor: "#dc2626",
                  color: "white",
                  border: "none",
                  padding: "6px 12px",
                  borderRadius: "6px",
                  cursor: "pointer",
                  marginLeft: "30px",
                }}
              >
                Logout
              </button>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}