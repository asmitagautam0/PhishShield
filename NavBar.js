"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export default function NavBar() {
  const pathname = usePathname();

  const isActive = (href) => pathname === href;

  return (
    <nav className="navbar">
      <div className="nav-inner">
        <div className="brand">PhishShield</div>

        <div className="nav-links">
          <Link className={isActive("/") ? "active" : ""} href="/">
            Login
          </Link>
          <Link className={isActive("/analyzer") ? "active" : ""} href="/analyzer">
            Analyzer
          </Link>
        </div>
      </div>
    </nav>
  );
}
